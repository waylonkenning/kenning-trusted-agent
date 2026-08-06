import React, { useContext, useState, useRef, useEffect } from 'react'
import { PortalContext } from '../PortalContext.jsx'
import { LoadingBlock, ErrorNotice, EmptyState, Stat, PageHeading, DataTable, CopyButton } from '../components/ui.jsx'
import { ConditionBuilder, ChainBuilder } from '../components/ConditionBuilder.jsx'
import ConfirmDialog from '../components/ConfirmDialog.jsx'
import {
  ArrowRight, ArrowsClockwise, ChartLineUp, CheckCircle, ClipboardText, Code,
  Eye, FileText, GearSix, Info, Key, LockKey, MagnifyingGlass, PencilSimple,
  Plus, ShieldCheck, SignOut, Trash, Upload, WarningCircle, X, XCircle,
} from '@phosphor-icons/react'
import { formatDate, sha256Hex, extractPdfText, runConcurrent } from '../lib.js'
import { useApiMutation } from '../hooks.js'

function CitationTrustView() {
  const { tenantId, data, load } = useContext(PortalContext)
  const findings = (data.audit?.events || []).filter((row) => String(row.event_type || '').startsWith('citation.'))
  const passed = findings.filter((row) => row.status === 'pass').length
  const needsReview = findings.filter((row) => ['warning', 'fail'].includes(row.status)).length
  const latest = findings[0]
  const [report, setReport] = useState(null)
  const [reportProgress, setReportProgress] = useState(null)
  const [reportError, setReportError] = useState(null)
  const [reportBusy, setReportBusy] = useState(false)
  const [apiRequest, { error: apiError }] = useApiMutation()

  async function verifyReport(event) {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    setReport(null)
    setReportError(null)
    setReportBusy(true)
    try {
      let reportText
      if (file.type === 'text/plain' || file.name.toLowerCase().endsWith('.txt')) {
        reportText = await file.text()
        setReportProgress({ phase: 'extracting', current: 1, total: 1 })
      } else if (file.type === 'application/pdf' || file.name.toLowerCase().endsWith('.pdf')) {
        reportText = await extractPdfText(file, setReportProgress)
      } else {
        throw new Error('Choose a PDF or extracted text file.')
      }
      if (!reportText.trim()) throw new Error('No text could be extracted from this report.')
      const contentSha256 = await sha256Hex(reportText)
      setReportProgress({ phase: 'manifest', current: 0, total: 1 })
      const manifest = await apiRequest(
        '/v1/citation-reports/extract',
        { method: 'POST', body: JSON.stringify({ report_name: file.name, report_text: reportText, content_sha256: contentSha256 }) },
        { reload: false },
      )
      const citations = manifest.citations || []
      const citationsById = new Map(citations.map((citation) => [citation.citation_id, citation]))
      const referenceClaimJobs = (manifest.reference_claims || []).filter((referenceClaim) => referenceClaim.claim_support_required === true).map((referenceClaim) => {
        const citation = citationsById.get(referenceClaim.citation_id)
        return citation ? { ...referenceClaim, job_type: 'reference_claim', job_id: referenceClaim.claim_id, url: citation.url, reference_metadata: citation.reference_metadata, category: 'reference_claim' } : null
      }).filter(Boolean)
      const verificationJobs = [...citations.map((citation) => ({ ...citation, job_type: 'citation', job_id: citation.citation_id })), ...referenceClaimJobs]
      const initial = {
        manifest,
        results: [],
        summary: null,
      }
      setReport(initial)
      setReportProgress({ phase: 'verifying', current: 0, total: verificationJobs.length })
      const results = await runConcurrent(
        verificationJobs,
        async (job) => {
          const claimSupportRequired = job.claim_support_required !== false
          const claim = claimSupportRequired ? (job.claim || '') : ''
          const mcp = await apiRequest(
            '/mcp/citation-trust',
            {
              method: 'POST',
              headers: { Accept: 'application/json, text/event-stream' },
              body: JSON.stringify({
                jsonrpc: '2.0',
                id: `${manifest.report_id}-${job.job_id}`,
                method: 'tools/call',
                params: {
                  name: 'verify_citations',
                  arguments: {
                    response: claim,
                    response_id: `${manifest.report_id}-${job.job_id}`,
                    citations: [{ url: job.url, claim, claim_support_required: claimSupportRequired, reference_metadata: job.reference_metadata }],
                  },
                },
              }),
            },
            { reload: false },
          )
          const result = mcp?.result?.structuredContent
          if (!result) throw new Error('Citation Trust MCP returned no structured result.')
          const finding = result.citations?.[0] || {}
          return { ...job, claim_support_required: claimSupportRequired, result, finding }
        },
        4,
        (_result, _index, completed) => setReportProgress({ phase: 'verifying', current: completed.filter(Boolean).length, total: verificationJobs.length }),
      )
      const successful = results.filter((item) => item && !item.error)
      const primaryResults = successful.filter((item) => item.job_type !== 'reference_claim')
      const completedPrimary = primaryResults.filter((item) => !item.error)
      const sourceFailures = completedPrimary.filter((item) => item.finding?.source_verified !== true)
      const claimChecked = successful.filter((item) => item.claim_support_required !== false)
      const claimFailures = claimChecked.filter((item) => item.finding?.supports_claim !== true)
      const claimPasses = claimChecked.filter((item) => item.finding?.supports_claim === true)
      const sourceOnly = completedPrimary.filter((item) => item.claim_support_required === false)
      const referenceClaims = successful.filter((item) => item.job_type === 'reference_claim')
      const metadataChecked = completedPrimary.filter((item) => item.reference_metadata)
      const metadataFailures = metadataChecked.filter((item) => item.finding?.reference_verified === false)
      const requestFailures = results.filter((item) => item?.error)
      const unresolvedReferences = (manifest.reference_markers || []).filter((item) => item.resolved !== true)
      const truncated = manifest.extraction?.truncated === true
      const credible = !truncated && unresolvedReferences.length === 0 && requestFailures.length === 0 && sourceFailures.length === 0 && claimFailures.length === 0 && metadataFailures.length === 0
      const summary = {
        status: credible ? 'pass' : 'fail',
        report_credibility: credible ? 'credible' : 'not_credible',
        citations_extracted: citations.length,
        citations_verified: completedPrimary.length,
        source_verified: completedPrimary.filter((item) => item.finding?.source_verified === true).length,
        verification_jobs: verificationJobs.length,
        verification_jobs_completed: successful.length,
        source_failures: sourceFailures.length,
        claim_support_checked: claimChecked.length,
        claim_support_passes: claimPasses.length,
        claim_support_failures: claimFailures.length,
        claim_support_not_applicable: sourceOnly.length,
        source_only_citations: sourceOnly.length,
        reference_claims_checked: referenceClaims.length,
        reference_claim_support_failures: claimFailures.filter((item) => item.job_type === 'reference_claim').length,
        bibliographic_references: (manifest.bibliographic_references || []).length,
        bibliographic_metadata_checked: metadataChecked.length,
        bibliographic_metadata_failures: metadataFailures.length,
        request_failures: requestFailures.length,
        transport_failures: requestFailures.length,
        unresolved_reference_markers: unresolvedReferences.length,
        resolved_reference_markers: (manifest.reference_markers || []).length - unresolvedReferences.length,
        extraction_truncated: truncated,
        citation_categories: manifest.extraction?.citation_categories || {},
        rule: 'Every source must be verified; only claim-bearing citations must also support their associated claim. Unresolved references or failed source checks make the report fail.',
      }
      setReport({ manifest, results, summary })
      setReportProgress({ phase: 'complete', current: verificationJobs.length, total: verificationJobs.length })
    } catch (caught) {
      setReportError(caught)
      setReportProgress(null)
    } finally {
      setReportBusy(false)
    }
  }
  return <>
    <PageHeading eyebrow="Citation Trust" title="Citation findings" description="Review whether an agent’s statements are supported by reliable sources you can open." action={<button className="portal-secondary-button" type="button" onClick={load}><ArrowsClockwise size={16} /> Refresh</button>} />
    <div className="portal-stat-grid">
      <Stat label="Responses verified" value={findings.length} detail="Current audit window" />
      <Stat label="Passed" value={passed} detail="Trust checks" tone="positive" />
      <Stat label="Needs review" value={needsReview} detail="Warnings or failures" tone={needsReview ? 'alert' : ''} />
      <Stat label="Latest check" value={latest?.status || '—'} detail={latest ? formatDate(latest.created_at) : 'No checks recorded'} tone={latest?.status === 'pass' ? 'positive' : latest ? 'alert' : ''} />
    </div>
    <div className="portal-content-grid">
      <section className="portal-panel portal-panel-wide">
        <div className="portal-panel-heading"><div><div className="portal-eyebrow">Source quality</div><h2>Recent citation findings</h2></div><span className="portal-panel-meta">Product view</span></div>
        <DataTable columns={[{ key: 'response_id', label: 'Response' }, { key: 'citation_count', label: 'Citations' }, { key: 'status', label: 'Status', render: (row) => <span className={`portal-pill ${row.status === 'pass' ? 'success' : row.status === 'fail' ? 'danger' : ''}`}>{row.status || 'recorded'}</span> }, { key: 'created_at', label: 'Time', render: (row) => formatDate(row.created_at) }]} rows={findings} empty="No citation verification events" />
      </section>
      <section className="portal-panel">
        <div className="portal-eyebrow">What Citation Trust checks</div>
        <h2>Evidence, not just links</h2>
        <ul className="portal-check-list"><li><CheckCircle size={17} weight="fill" /><span>Whether the source exists and can be opened.</span></li><li><CheckCircle size={17} weight="fill" /><span>Whether the source supports the statement.</span></li><li><CheckCircle size={17} weight="fill" /><span>How current and reliable the source is, and the workspace rules for getting it.</span></li></ul>
        <p className="portal-field-note">Checks appear here when Citation Trust is called through the API or MCP.</p>
      </section>
    </div>
    <section className="portal-panel portal-report-verifier">
      <div className="portal-panel-heading"><div><div className="portal-eyebrow">Check a report</div><h2>Check a real report</h2></div><label className="portal-primary-button portal-file-button" htmlFor="citation-report-upload">{reportBusy ? 'Processing…' : 'Upload PDF'} <ArrowRight size={16} /></label><input id="citation-report-upload" className="portal-visually-hidden" type="file" accept="application/pdf,.pdf,text/plain,.txt" onChange={verifyReport} disabled={reportBusy} /></div>
      <p className="portal-field-note">The PDF is read in your browser. Kenning then finds every URL and reference marker, and checks each source with Citation Trust. The original report is not stored.</p>
      {reportProgress && <div className="portal-report-progress" role="status"><span>{reportProgress.phase === 'extracting' ? `Extracting page ${reportProgress.current} of ${reportProgress.total}` : reportProgress.phase === 'manifest' ? 'Building citation list…' : reportProgress.phase === 'verifying' ? `Checking source ${reportProgress.current} of ${reportProgress.total}` : 'Check complete'}</span><progress value={reportProgress.total ? reportProgress.current : 0} max={reportProgress.total || 1} /></div>}
      <ErrorNotice error={reportError || apiError} />
      {report?.summary && <div className={`portal-report-summary ${report.summary.status === 'pass' ? 'success' : 'failure'}`} role="status"><div><span className="portal-eyebrow">Report check</span><strong>{report.summary.status === 'pass' ? 'PASS' : 'FAIL'}</strong></div><div className="portal-report-summary-grid"><span><b>{report.summary.citations_extracted}</b> URLs found</span><span><b>{report.summary.bibliographic_references}</b> bibliography entries</span><span><b>{report.summary.bibliographic_metadata_failures}</b> metadata mismatches</span><span><b>{report.summary.claim_support_checked}</b> claim checks</span><span><b>{report.summary.claim_support_failures}</b> claims unsupported</span><span><b>{report.summary.source_failures}</b> sources unverified</span><span><b>{report.summary.transport_failures}</b> transport failures</span><span><b>{report.summary.source_only_citations}</b> source-only links</span><span><b>{report.summary.unresolved_reference_markers}</b> references unmatched</span></div><p>{report.summary.rule}</p></div>}
      {report?.manifest && <div className="portal-report-details"><div className="portal-report-manifest"><span><b>Report</b> {report.manifest.report_name}</span><span><b>Pages</b> {report.manifest.page_count}</span><span><b>File fingerprint (SHA-256)</b> <code>{report.manifest.content_sha256}</code></span></div><div className="portal-report-warning"><Info size={17} /><span>Bibliography entries, source footers, data downloads, licence pages, and corrigenda are source-only checks. In-text reference markers are checked against the claim-bearing sentence where they occur. Transport failures are reported separately from source and claim failures.</span></div><div className="portal-table-wrap"><table className="portal-table"><thead><tr><th>Page</th><th>URL</th><th>Type</th><th>Source</th><th>Statement or context</th><th>Result</th></tr></thead><tbody>{report.results.map((item) => <tr key={item.job_id || item.claim_id || item.citation_id}><td>{item.page}</td><td><a className="portal-text-link" href={item.url} target="_blank" rel="noreferrer">{item.url}</a></td><td><span className="portal-pill">{item.category || (item.job_type === 'reference_claim' ? 'reference claim' : 'claim')}</span></td><td>{item.error ? <span className="portal-pill danger">transport failed</span> : <span className={`portal-pill ${item.finding?.source_verified ? 'success' : 'danger'}`}>{item.finding?.source_verified ? 'verified' : 'failed'}</span>}</td><td>{item.claim}</td><td>{item.error ? <span className="portal-pill danger">transport failure</span> : item.job_type === 'reference_claim' ? <span className={`portal-pill ${item.finding?.supports_claim ? 'success' : 'danger'}`}>{item.finding?.supports_claim ? 'claim supported' : 'claim unsupported'}</span> : item.claim_support_required === false ? item.reference_metadata ? <span className={`portal-pill ${item.finding?.reference_verified === false ? 'danger' : 'success'}`}>{item.finding?.reference_verified === false ? 'metadata mismatch' : 'metadata checked'}</span> : <span className="portal-pill">source checked</span> : <span className={`portal-pill ${item.finding?.supports_claim ? 'success' : 'danger'}`}>{item.finding?.supports_claim ? 'supported' : 'unsupported'}</span>}</td></tr>)}</tbody></table></div>{report.manifest.reference_markers?.filter((item) => item.resolved !== true).length > 0 && <div className="portal-report-warning"><WarningCircle size={17} /><span>{report.manifest.reference_markers.filter((item) => item.resolved !== true).length} reference markers could not be matched to bibliography URLs and count as failures under the strict report rule.</span></div>}</div>}
    </section>
  </>
}


export default CitationTrustView

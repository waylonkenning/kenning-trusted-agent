import React, { useMemo, useState } from 'react'
import { ArrowLeft, ArrowRight, BookOpenText, CheckCircle, MagnifyingGlass } from '@phosphor-icons/react'
import { PageHeading } from '../components/ui.jsx'
import { USER_GUIDE_TOPICS } from '../data/userGuide.js'

function UserGuideView({ onBack }) {
  const [query, setQuery] = useState('')
  const [activeId, setActiveId] = useState(USER_GUIDE_TOPICS[0]?.id || '')
  const filteredTopics = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase()
    if (!normalizedQuery) return USER_GUIDE_TOPICS
    return USER_GUIDE_TOPICS.filter((topic) => [topic.title, topic.boardTitle, topic.category, topic.summary].join(' ').toLowerCase().includes(normalizedQuery))
  }, [query])
  const activeTopic = USER_GUIDE_TOPICS.find((topic) => topic.id === activeId) || USER_GUIDE_TOPICS[0]

  function chooseTopic(topic) {
    setActiveId(topic.id)
    document.querySelector('.portal-guide-article')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  if (!activeTopic) return null

  return <>
    <PageHeading
      eyebrow="Workspace help"
      title="User guide"
      description="Practical instructions for the completed features in the Kenning console. Each topic is linked to its Delivery Board Feature card."
      action={<button className="portal-secondary-button" type="button" onClick={onBack}><ArrowLeft size={16} /> Back to settings</button>}
    />
    <div className="portal-guide-intro" role="note">
      <BookOpenText size={24} weight="duotone" />
      <div><strong>{USER_GUIDE_TOPICS.length} feature topics</strong><span>Use search to find a feature, then follow the steps and screenshot in its topic.</span></div>
    </div>
    <div className="portal-guide-layout">
      <aside className="portal-panel portal-guide-index" aria-label="User guide topics">
        <div className="portal-guide-index-heading"><div><div className="portal-eyebrow">Topics</div><h2>Find a feature</h2></div><span className="portal-pill">{filteredTopics.length}</span></div>
        <label className="portal-guide-search" htmlFor="user-guide-search"><MagnifyingGlass size={16} /><span className="portal-visually-hidden">Search user guide</span><input id="user-guide-search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search topics" /></label>
        <div className="portal-guide-topic-list">
          {filteredTopics.map((topic) => <button className={`portal-guide-topic ${topic.id === activeTopic.id ? 'active' : ''}`} data-issue-number={topic.issue} key={topic.id} type="button" onClick={() => chooseTopic(topic)}>
            <span className="portal-guide-topic-issue">#{topic.issue}</span><span><strong>{topic.title}</strong><small>{topic.category}</small></span>
          </button>)}
          {!filteredTopics.length && <p className="portal-field-note">No topics match this search.</p>}
        </div>
      </aside>
      <article className="portal-panel portal-guide-article" data-testid="user-guide-topic">
        <div className="portal-guide-article-heading"><div><div className="portal-eyebrow">{activeTopic.category}</div><h2>{activeTopic.title}</h2></div><span className="portal-guide-issue">Delivery Board #{activeTopic.issue}</span></div>
        <p className="portal-guide-board-title">{activeTopic.boardTitle}</p>
        <p className="portal-guide-summary">{activeTopic.summary}</p>
        <div className="portal-guide-location"><span>Where to find it</span><strong>{activeTopic.where}</strong></div>
        <div className="portal-guide-section"><div className="portal-eyebrow">How it works</div><ol className="portal-guide-steps">{activeTopic.steps.map((step) => <li key={step}><CheckCircle size={17} weight="duotone" /><span>{step}</span></li>)}</ol></div>
        <figure className="portal-guide-screenshot"><img src={activeTopic.screenshot} alt={activeTopic.screenshotAlt} /><figcaption>{activeTopic.caption}</figcaption></figure>
        <div className="portal-guide-footer"><span>Topic {USER_GUIDE_TOPICS.findIndex((topic) => topic.id === activeTopic.id) + 1} of {USER_GUIDE_TOPICS.length}</span><button className="portal-text-link" type="button" onClick={() => { const currentIndex = USER_GUIDE_TOPICS.findIndex((topic) => topic.id === activeTopic.id); const nextTopic = USER_GUIDE_TOPICS[(currentIndex + 1) % USER_GUIDE_TOPICS.length]; chooseTopic(nextTopic) }}>Next topic <ArrowRight size={15} /></button></div>
      </article>
    </div>
  </>
}

export default UserGuideView

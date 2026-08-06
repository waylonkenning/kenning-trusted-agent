import React, { useEffect, useRef } from 'react'

/**
 * Accessible confirmation dialog with focus trap (#260).
 *
 * - Focuses the cancel button on mount
 * - Traps Tab within the dialog
 * - Restores focus to the trigger element on close
 * - Closes on Escape
 */
export default function ConfirmDialog({ title, eyebrow = 'Confirm', message, cancelLabel = 'Cancel', confirmLabel = 'Confirm', confirmClass = 'portal-primary-button', onCancel, onConfirm, disabled = false }) {
  const dialogRef = useRef(null)
  const cancelRef = useRef(null)
  const triggerRef = useRef(null)

  useEffect(() => {
    // Remember what opened us so we can restore focus on close.
    triggerRef.current = document.activeElement
    cancelRef.current?.focus()

    function handleKeyDown(event) {
      if (event.key === 'Escape') {
        event.preventDefault()
        onCancel()
        return
      }
      if (event.key !== 'Tab') return
      const focusable = dialogRef.current?.querySelectorAll('button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])')
      if (!focusable?.length) return
      const first = focusable[0]
      const last = focusable[focusable.length - 1]
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first.focus()
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => {
      document.removeEventListener('keydown', handleKeyDown)
      // Restore focus to the element that opened the dialog.
      triggerRef.current?.focus?.()
    }
  }, [onCancel])

  return (
    <div className="portal-policy-confirmation" role="alertdialog" aria-modal="true" aria-labelledby="confirm-dialog-title" ref={dialogRef}>
      <div className="portal-eyebrow">{eyebrow}</div>
      <h2 id="confirm-dialog-title">{title}</h2>
      <p>{message}</p>
      <div className="portal-row-actions">
        <button className="portal-secondary-button" type="button" onClick={onCancel} disabled={disabled} ref={cancelRef}>{cancelLabel}</button>
        <button className={confirmClass} type="button" onClick={onConfirm} disabled={disabled}>{confirmLabel}</button>
      </div>
    </div>
  )
}

import type { HostKeyInfo } from './socket'

export interface HostKeyDialogProps {
  info: HostKeyInfo
  onAccept: () => void
  onReject: () => void
}

/**
 * HostKeyDialog asks the user to approve a host key they have not seen.
 *
 * Written to be answerable rather than dismissable. The usual version of this
 * dialog offers "yes" as the obvious button and buries the fingerprint in
 * small type, which trains people to accept anything. Here the fingerprint is
 * the largest thing on screen, the buttons are equally weighted, and neither
 * is preselected — nothing about the layout suggests an answer.
 */
export function HostKeyDialog({ info, onAccept, onReject }: HostKeyDialogProps) {
  return (
    <div className="pane-overlay">
      <div className="card" role="alertdialog" aria-label="Unrecognised host key">
        <h2>You have not connected to this host before</h2>
        <p>
          <strong>{info.hostname}:{info.port}</strong> is offering a{' '}
          {info.key_type} key. Nothing has been sent to it yet.
        </p>

        <p className="fingerprint" data-testid="host-key-fingerprint">
          {info.fingerprint}
        </p>

        <p className="muted">
          Accept only if this matches the fingerprint you obtained from the
          host itself — <code>ssh-keygen -lf /etc/ssh/ssh_host_{'{'}type{'}'}_key.pub</code>{' '}
          on the console, or whatever your build process records. Accepting a
          fingerprint you have not checked is how a machine-in-the-middle gets
          your password.
        </p>

        <div className="row">
          <button onClick={onReject}>Do not connect</button>
          <button onClick={onAccept}>The fingerprint matches — connect</button>
        </div>
      </div>
    </div>
  )
}

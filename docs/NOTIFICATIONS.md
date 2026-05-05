# Notification Configuration Guide

This document explains how to configure notifications for the claude-secure-coding-rules repository.

## Automatic Review Requests

The repository uses **CODEOWNERS** to automatically request reviews from maintainers when PRs are created. This ensures owners are notified via email (based on their GitHub notification settings).

### How It Works

1. Contributor creates a PR
2. GitHub reads `.github/CODEOWNERS`
3. Matching code owners are automatically requested as reviewers
4. Requested reviewers receive email notifications (if enabled in their settings)

## Configuring Your Email Notifications

To receive email notifications for this repository:

### 1. Watch the Repository

1. Go to [TikiTribe/claude-secure-coding-rules](https://github.com/TikiTribe/claude-secure-coding-rules)
2. Click **Watch** dropdown (top right)
3. Select **All Activity** or **Custom** > check:
   - Pull requests
   - Issues
   - Discussions

### 2. Configure Email Preferences

1. Go to [GitHub Settings > Notifications](https://github.com/settings/notifications)
2. Under **Email notification preferences**:
   - Enable "Email" for "Participating, @mentions and custom"
   - Enable "Email" for "Watching"
3. Under **Custom routing** (optional):
   - Route TikiTribe notifications to a specific email

### 3. Verify Email Settings

1. Go to [GitHub Settings > Emails](https://github.com/settings/emails)
2. Ensure your email is verified
3. Check "Receive all emails" is enabled (not blocked)

## Notification Triggers

| Event | Who Gets Notified |
|-------|------------------|
| New PR created | CODEOWNERS (auto-requested reviewers) |
| PR comment | PR author, reviewers, mentioned users |
| PR review | PR author |
| Issue created | Watchers with "All Activity" |
| Issue comment | Issue author, mentioned users |
| @mention | Mentioned user |
| Review requested | Requested reviewer |

## Troubleshooting

### Not Receiving Emails?

1. Check spam/junk folder
2. Verify email in GitHub settings
3. Check notification settings aren't set to "Web only"
4. Ensure you're watching the repo or are a CODEOWNER
5. Check if notifications are being routed to a different email

### Too Many Emails?

1. Change watch setting to "Participating and @mentions"
2. Use custom routing to send to a filtered inbox
3. Create email filters for `notifications@github.com`

## Organization Settings (Admins)

Organization owners can configure default notification settings:

1. Go to Organization Settings > Member privileges
2. Configure default repository permission
3. Set up team notification preferences

## CI/CD Notifications

GitHub Actions failures are visible in:
- PR status checks
- Email (if configured in workflow with `actions/github-script`)
- GitHub mobile app push notifications

The CI workflow comments coverage reports directly on PRs for visibility.

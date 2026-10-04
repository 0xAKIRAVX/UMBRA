package com.umbra.scanner.core

/**
 * Project identity — single source of truth for repo links, update channel
 * and creator credits shown in-app and used by the update checker.
 */
object Project {
    const val NAME = "UMBRA"
    const val CREATOR = "0xAKIRAVX"

    const val GITHUB_USER = "0xAKIRAVX"
    const val GITHUB_REPO = "UMBRA"

    /** Human-facing repository page. */
    const val REPO_URL = "https://github.com/$GITHUB_USER/$GITHUB_REPO"

    /** Human-facing releases page (what the update dialog opens). */
    const val RELEASES_URL = "$REPO_URL/releases"

    /** Latest-release JSON endpoint used by the in-app update checker. */
    const val LATEST_API = "https://api.github.com/repos/$GITHUB_USER/$GITHUB_REPO/releases/latest"
}

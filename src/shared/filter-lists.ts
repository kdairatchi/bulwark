// Filter lists power the Secure DNS resolver's system-wide blocking (like
// Portmaster's trusted lists). A curated catalog is downloaded, parsed to
// domains, cached locally, and merged into the resolver block set.

export type FilterListCategory = 'ads' | 'tracking' | 'ads+tracking' | 'malware' | 'ads+malware'

export interface FilterListInfo {
  id: string
  name: string
  description: string
  category: FilterListCategory
  url: string
  enabledByDefault: boolean
}

/** Per-list runtime state (enabled, cached domain count, freshness). */
export interface FilterListStatus {
  id: string
  name: string
  description: string
  category: FilterListCategory
  enabled: boolean
  /** Domains parsed from the cached copy (0 if never synced). */
  domainCount: number
  cached: boolean
  updatedAt: string | null
  lastError?: string
}

export interface FilterListsState {
  lists: FilterListStatus[]
  /** Deduped domain total across all enabled+cached lists. */
  totalDomains: number
}

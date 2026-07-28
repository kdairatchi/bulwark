import { motion } from 'framer-motion'
import { cn } from '@/lib/utils'
import type { LucideIcon } from 'lucide-react'

interface EmptyStateProps {
  icon: LucideIcon
  title: string
  description: string
  action?: React.ReactNode
  className?: string
}

export function EmptyState({ icon: Icon, title, description, action, className }: EmptyStateProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className={cn('flex flex-col items-center justify-center py-20', className)}
    >
      <div
        className="mb-5 flex h-16 w-16 items-center justify-center rounded-2xl"
        style={{ background: 'var(--bg-subtle)' }}
        aria-hidden="true"
      >
        <Icon className="h-7 w-7" style={{ color: 'var(--text-faint)' }} strokeWidth={1.5} />
      </div>
      <h3 className="text-[15px] font-medium" style={{ color: 'var(--text-muted)' }}>{title}</h3>
      <p className="mt-1.5 max-w-sm text-center text-[13px]" style={{ color: 'var(--text-muted)' }}>
        {description}
      </p>
      {action && (
        <motion.div
          className="mt-5"
          initial={{ opacity: 0, y: 4 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.08, duration: 0.2 }}
        >
          {action}
        </motion.div>
      )}
    </motion.div>
  )
}

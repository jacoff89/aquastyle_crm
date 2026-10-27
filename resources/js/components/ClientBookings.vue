<script setup>
import { Link } from '@inertiajs/vue3';

defineProps({
    /** Занятия клиента: { eventId, title, dateLabel, timeLabel, location, leadInstructor, isEventCancelled, status, statusLabel, calendarUrl }. */
    rows: { type: Array, required: true },
    emptyTitle: { type: String, required: true },
    emptyText: { type: String, required: true },
    /** Подпись к списку для чтения с экрана. */
    label: { type: String, required: true },
});

const statusClasses = {
    booked: 'bg-sea-50 text-sea-700',
    attended: 'bg-emerald-50 text-emerald-800',
    no_show: 'bg-red-50 text-flag',
    cancelled: 'bg-surface text-muted',
};
</script>

<template>
    <ul v-if="rows.length" class="divide-y divide-line rounded-lg border border-line bg-white" :aria-label="label">
        <li v-for="row in rows" :key="row.eventId" class="flex flex-wrap items-start justify-between gap-x-4 gap-y-2 px-5 py-3 text-sm">
            <div class="min-w-0">
                <Link :href="row.calendarUrl" class="font-medium text-ink underline-offset-4 hover:underline">{{ row.title }}</Link>
                <p class="mt-0.5 text-muted">
                    {{ row.dateLabel }}, {{ row.timeLabel }}<span v-if="row.location"> · {{ row.location }}</span>
                </p>
                <p v-if="row.leadInstructor" class="text-muted">Ведущий: {{ row.leadInstructor }}</p>
            </div>
            <span
                class="shrink-0 rounded-full px-2.5 py-0.5 text-xs font-medium"
                :class="row.isEventCancelled ? statusClasses.cancelled : statusClasses[row.status]"
            >
                {{ row.isEventCancelled ? 'Занятие отменено' : row.statusLabel }}
            </span>
        </li>
    </ul>

    <div v-else class="rounded-lg border border-dashed border-line bg-white px-6 py-10 text-center">
        <p class="text-base font-medium text-ink">{{ emptyTitle }}</p>
        <p class="mx-auto mt-2 max-w-md text-sm leading-6 text-muted">{{ emptyText }}</p>
    </div>
</template>

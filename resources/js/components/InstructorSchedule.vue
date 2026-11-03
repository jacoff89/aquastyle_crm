<script setup>
import { Link, router } from '@inertiajs/vue3';
import SelectInput from './SelectInput.vue';

defineProps({
    /** Занятия: { id, title, date, dateLabel, time, location, clientsCount, isCancelled }. */
    schedule: { type: Array, required: true },
    scheduleRange: { type: String, required: true },
    /** Периоды расписания: { value, label }. */
    scheduleRanges: { type: Array, required: true },
});

const changeRange = (event) => {
    router.patch('/schedule-range', { range: event.target.value }, { preserveScroll: true, only: ['schedule', 'scheduleRange'] });
};
</script>

<template>
    <section aria-labelledby="schedule-heading">
        <div class="flex flex-wrap items-center justify-between gap-3">
            <h2 id="schedule-heading" class="text-lg font-semibold">Расписание на ближайшее время</h2>
            <div class="w-40">
                <label for="schedule-range" class="sr-only">Период расписания</label>
                <SelectInput id="schedule-range" :model-value="scheduleRange" @change="changeRange">
                    <option v-for="range in scheduleRanges" :key="range.value" :value="range.value">{{ range.label }}</option>
                </SelectInput>
            </div>
        </div>
        <ul v-if="schedule.length" class="mt-3 divide-y divide-line rounded-lg border border-line bg-white">
            <li v-for="event in schedule" :key="event.id">
                <Link
                    :href="`/calendar?view=day&date=${event.date}`"
                    class="flex flex-wrap items-baseline gap-x-4 gap-y-1 px-5 py-3 text-sm transition-colors hover:bg-surface"
                >
                    <span class="w-32 shrink-0 text-muted first-letter:uppercase">{{ event.dateLabel }}</span>
                    <span class="w-24 shrink-0 tabular-nums">{{ event.time }}</span>
                    <span class="min-w-0 flex-1" :class="{ 'text-muted line-through': event.isCancelled }">
                        <span class="font-medium text-ink">{{ event.title }}</span>
                        <span v-if="event.location" class="text-muted"> · {{ event.location }}</span>
                    </span>
                    <span class="shrink-0 text-xs text-muted tabular-nums" title="Клиентов на занятии">
                        Клиентов: {{ event.clientsCount }}
                    </span>
                </Link>
            </li>
        </ul>
        <div v-else class="mt-3 rounded-lg border border-dashed border-line bg-white px-6 py-10 text-center">
            <p class="text-base font-medium text-ink">Занятий пока нет</p>
            <p class="mx-auto mt-2 max-w-md text-sm leading-6 text-muted">
                В выбранный период занятий в календаре нет.
            </p>
        </div>
    </section>
</template>

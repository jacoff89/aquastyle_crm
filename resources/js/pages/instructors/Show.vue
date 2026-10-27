<script setup>
import { Link } from '@inertiajs/vue3';
import AppLayout from '../../layouts/AppLayout.vue';

defineProps({
    instructor: { type: Object, required: true },
    schedule: { type: Array, required: true },
});
</script>

<template>
    <AppLayout :title="instructor.name">
        <template #actions>
            <Link
                :href="`/instructors/${instructor.id}/edit`"
                class="inline-flex items-center rounded-md border border-line bg-white px-4 py-2 text-sm font-medium text-ink transition-colors hover:bg-surface"
            >
                Редактировать
            </Link>
        </template>

        <div class="max-w-2xl space-y-8">
            <section class="rounded-lg border border-line bg-white p-6" aria-labelledby="contacts-heading">
                <div class="flex items-center justify-between gap-4">
                    <h2 id="contacts-heading" class="text-lg font-semibold">Контакты</h2>
                    <span
                        class="inline-block rounded px-2 py-0.5 text-xs"
                        :class="instructor.isActive ? 'bg-sea-50 text-sea-700' : 'bg-slate-100 text-muted'"
                    >
                        {{ instructor.isActive ? 'Активен' : 'Отключён' }}
                    </span>
                </div>

                <dl class="mt-4 grid gap-x-6 gap-y-4 text-sm sm:grid-cols-2">
                    <div>
                        <dt class="text-muted">Email</dt>
                        <dd class="mt-0.5 text-ink">{{ instructor.email }}</dd>
                    </div>
                    <div>
                        <dt class="text-muted">Телефон</dt>
                        <dd class="mt-0.5 text-ink">{{ instructor.phone || '—' }}</dd>
                    </div>
                    <div>
                        <dt class="text-muted">Цвет в календаре</dt>
                        <dd class="mt-0.5 flex items-center gap-2 text-ink">
                            <span class="size-4 rounded-full" :style="{ backgroundColor: instructor.color }" aria-hidden="true" />
                            {{ instructor.color }}
                        </dd>
                    </div>
                    <div v-if="instructor.notes" class="sm:col-span-2">
                        <dt class="text-muted">Заметки</dt>
                        <dd class="mt-0.5 whitespace-pre-line text-ink">{{ instructor.notes }}</dd>
                    </div>
                </dl>
            </section>

            <section aria-labelledby="schedule-heading">
                <h2 id="schedule-heading" class="text-lg font-semibold">Расписание на ближайшие две недели</h2>
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
                            <span class="text-xs text-muted">
                                {{ event.role }}<template v-if="event.status !== 'planned'"> · {{ event.statusLabel }}</template>
                            </span>
                        </Link>
                    </li>
                </ul>
                <div v-else class="mt-3 rounded-lg border border-dashed border-line bg-white px-6 py-10 text-center">
                    <p class="text-base font-medium text-ink">Занятий пока нет</p>
                    <p class="mx-auto mt-2 max-w-md text-sm leading-6 text-muted">
                        В ближайшие две недели у инструктора нет занятий в календаре.
                    </p>
                </div>
            </section>

            <Link href="/instructors" class="inline-block text-sm text-muted hover:text-ink">← Все инструкторы</Link>
        </div>
    </AppLayout>
</template>

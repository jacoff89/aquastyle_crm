<script setup>
import { Link } from '@inertiajs/vue3';
import InstructorSchedule from '../../components/InstructorSchedule.vue';
import AppLayout from '../../layouts/AppLayout.vue';

defineProps({
    instructor: { type: Object, required: true },
    schedule: { type: Array, required: true },
    scheduleRange: { type: String, required: true },
    /** Периоды расписания: { value, label }. */
    scheduleRanges: { type: Array, required: true },
});
</script>

<template>
    <AppLayout :title="[instructor.name, instructor.lastName].filter(Boolean).join(' ')">
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
                    <div>
                        <dt class="text-muted">Снаряжение</dt>
                        <dd class="mt-0.5 text-ink">
                            <Link
                                v-if="instructor.equipmentCount"
                                :href="`/equipment?instructor=${instructor.id}`"
                                class="text-sea-700 underline-offset-4 hover:underline"
                            >
                                Закреплено: {{ instructor.equipmentCount }}
                            </Link>
                            <span v-else>—</span>
                        </dd>
                    </div>
                    <div v-if="instructor.notes" class="sm:col-span-2">
                        <dt class="text-muted">Заметки</dt>
                        <dd class="mt-0.5 whitespace-pre-line text-ink">{{ instructor.notes }}</dd>
                    </div>
                </dl>
            </section>

            <InstructorSchedule :schedule="schedule" :schedule-range="scheduleRange" :schedule-ranges="scheduleRanges" />

            <Link href="/instructors" class="inline-block text-sm text-muted hover:text-ink">← Все инструкторы</Link>
        </div>
    </AppLayout>
</template>

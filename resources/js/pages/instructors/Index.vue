<script setup>
import { Link } from '@inertiajs/vue3';
import AppIcon from '../../components/AppIcon.vue';
import AppLayout from '../../layouts/AppLayout.vue';

defineProps({
    instructors: { type: Array, required: true },
});
</script>

<template>
    <AppLayout title="Инструкторы">
        <template #actions>
            <Link
                href="/instructors/create"
                class="inline-flex items-center rounded-md bg-sea-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-sea-700"
            >
                <AppIcon name="plus" />
                <span class="ml-1.5">Добавить инструктора</span>
            </Link>
        </template>

        <p class="max-w-2xl text-sm leading-6 text-muted">
            Цвет инструктора будет отмечать его занятия в календаре. Отключённый инструктор не может войти и пропадает из
            выбора, а прошлые занятия остаются за ним.
        </p>

        <div
            v-if="instructors.length === 0"
            class="mt-6 rounded-lg border border-dashed border-line bg-white px-6 py-12 text-center"
        >
            <p class="text-base font-medium text-ink">Инструкторов пока нет</p>
            <p class="mx-auto mt-2 max-w-md text-sm leading-6 text-muted">
                Добавьте первого инструктора, чтобы назначать его на занятия.
            </p>
        </div>

        <div v-else class="mt-6 overflow-hidden rounded-lg border border-line bg-white">
            <table class="w-full text-left text-sm">
                <thead class="hidden border-b border-line bg-surface text-muted sm:table-header-group">
                    <tr>
                        <th scope="col" class="px-4 py-2.5 font-medium">Инструктор</th>
                        <th scope="col" class="hidden px-4 py-2.5 font-medium md:table-cell">Контакты</th>
                        <th scope="col" class="px-4 py-2.5 font-medium">Статус</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-line">
                    <tr v-for="instructor in instructors" :key="instructor.id" class="flex flex-col px-4 py-3 sm:table-row sm:p-0">
                        <td class="sm:px-4 sm:py-3">
                            <div class="flex items-center gap-3">
                                <span
                                    class="size-3 shrink-0 rounded-full"
                                    :class="{ 'opacity-40': !instructor.isActive }"
                                    :style="{ backgroundColor: instructor.color }"
                                    aria-hidden="true"
                                />
                                <Link
                                    :href="`/instructors/${instructor.id}`"
                                    class="font-medium underline-offset-4 hover:text-sea-700 hover:underline"
                                    :class="instructor.isActive ? 'text-ink' : 'text-muted'"
                                >
                                    {{ instructor.name }}
                                </Link>
                                <span v-if="instructor.isAdmin" class="rounded bg-depth-900/10 px-1.5 py-0.5 text-xs text-depth-800">
                                    Администратор
                                </span>
                            </div>
                        </td>
                        <td class="hidden px-4 py-3 text-muted md:table-cell">
                            <div>{{ instructor.email }}</div>
                            <div v-if="instructor.phone">{{ instructor.phone }}</div>
                        </td>
                        <td class="sm:px-4 sm:py-3">
                            <span
                                class="inline-block rounded px-2 py-0.5 text-xs"
                                :class="instructor.isActive ? 'bg-sea-50 text-sea-700' : 'bg-slate-100 text-muted'"
                            >
                                {{ instructor.isActive ? 'Активен' : 'Отключён' }}
                            </span>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </AppLayout>
</template>

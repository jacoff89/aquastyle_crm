<script setup>
import { Link } from '@inertiajs/vue3';
import AppIcon from '../../../components/AppIcon.vue';
import AppLayout from '../../../layouts/AppLayout.vue';

defineProps({
    users: { type: Array, required: true },
});
</script>

<template>
    <AppLayout title="Пользователи">
        <template #actions>
            <Link
                href="/settings/users/create"
                class="inline-flex items-center rounded-md bg-sea-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-sea-700"
            >
                <AppIcon name="plus" />
                <span class="ml-1.5">Добавить пользователя</span>
            </Link>
        </template>

        <p class="max-w-2xl text-sm leading-6 text-muted">
            Администраторы управляют справочниками и учётными записями. Инструкторы ведут календарь и клиентов.
            Отключённый пользователь не может войти, но его история сохраняется.
        </p>

        <div class="mt-6 overflow-hidden rounded-lg border border-line bg-white">
            <table class="w-full text-left text-sm">
                <thead class="hidden border-b border-line bg-surface text-muted sm:table-header-group">
                    <tr>
                        <th scope="col" class="px-4 py-2.5 font-medium">Имя</th>
                        <th scope="col" class="px-4 py-2.5 font-medium">Роль</th>
                        <th scope="col" class="hidden px-4 py-2.5 font-medium md:table-cell">Контакты</th>
                        <th scope="col" class="px-4 py-2.5 font-medium">Статус</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-line">
                    <tr v-for="user in users" :key="user.id" class="flex flex-col px-4 py-3 sm:table-row sm:p-0">
                        <td class="sm:px-4 sm:py-3">
                            <Link
                                :href="`/settings/users/${user.id}/edit`"
                                class="font-medium text-ink underline-offset-4 hover:text-sea-700 hover:underline"
                                :class="{ 'text-muted': !user.isActive }"
                            >
                                {{ user.name }}
                            </Link>
                            <span v-if="user.isCurrentUser" class="ml-2 text-xs text-muted">это вы</span>
                        </td>
                        <td class="text-muted sm:px-4 sm:py-3 sm:text-ink">{{ user.roleLabel }}</td>
                        <td class="hidden px-4 py-3 text-muted md:table-cell">
                            <div>{{ user.email }}</div>
                            <div v-if="user.phone">{{ user.phone }}</div>
                        </td>
                        <td class="sm:px-4 sm:py-3">
                            <span
                                class="inline-block rounded px-2 py-0.5 text-xs"
                                :class="user.isActive ? 'bg-sea-50 text-sea-700' : 'bg-slate-100 text-muted'"
                            >
                                {{ user.isActive ? 'Активен' : 'Отключён' }}
                            </span>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </AppLayout>
</template>

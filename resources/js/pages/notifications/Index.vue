<script setup>
import { Link, router } from '@inertiajs/vue3';
import AppLayout from '../../layouts/AppLayout.vue';

defineProps({
    /** Страница уведомлений: { data: [{ id, message, actorName, createdAtLabel, isRead, hasLink }], currentPage, lastPage, total, previousPageUrl, nextPageUrl }. */
    notices: { type: Object, required: true },
    /** Какие показаны: «all» или «unread». */
    filter: { type: String, required: true },
    /** Есть ли непрочитанные среди всех доступных уведомлений, а не только на этой странице. */
    hasUnread: { type: Boolean, required: true },
});

const filters = [
    { value: 'all', label: 'Все', href: '/notifications' },
    { value: 'unread', label: 'Непрочитанные', href: '/notifications?filter=unread' },
];

const readAll = () => {
    router.post('/notifications/read-all', {}, { preserveScroll: true });
};
</script>

<template>
    <AppLayout title="Уведомления">
        <template #actions>
            <div class="flex flex-wrap gap-2">
                <button
                    v-if="hasUnread"
                    type="button"
                    class="rounded-md border border-line bg-white px-3 py-1.5 text-sm text-ink hover:bg-surface"
                    @click="readAll"
                >
                    Отметить все прочитанными
                </button>
                <Link
                    href="/notifications/settings"
                    class="rounded-md border border-line bg-white px-3 py-1.5 text-sm text-ink hover:bg-surface"
                >
                    Telegram и настройки
                </Link>
            </div>
        </template>

        <nav class="flex gap-1" aria-label="Какие уведомления показать">
            <Link
                v-for="item in filters"
                :key="item.value"
                :href="item.href"
                class="rounded-md px-3 py-1.5 text-sm font-medium transition-colors"
                :class="filter === item.value ? 'bg-sea-600 text-white' : 'text-muted hover:bg-sea-50 hover:text-sea-700'"
                :aria-current="filter === item.value ? 'page' : undefined"
                preserve-scroll
            >
                {{ item.label }}
            </Link>
        </nav>

        <ul class="mt-4 max-w-3xl divide-y divide-line rounded-lg border border-line bg-white">
            <li v-for="notice in notices.data" :key="notice.id">
                <Link
                    :href="`/notifications/${notice.id}/open`"
                    method="post"
                    as="button"
                    class="flex w-full items-start gap-3 px-3 py-3 text-left transition-colors hover:bg-surface sm:px-4"
                    :class="{ 'cursor-default': !notice.hasLink && notice.isRead }"
                    preserve-scroll
                >
                    <span
                        class="mt-1.5 size-2 shrink-0 rounded-full"
                        :class="notice.isRead ? 'bg-transparent' : 'bg-flag'"
                        aria-hidden="true"
                    />
                    <span class="min-w-0 flex-1">
                        <span class="block text-sm leading-6" :class="notice.isRead ? 'text-ink' : 'font-semibold text-ink'">
                            <span v-if="!notice.isRead" class="sr-only">Непрочитанное: </span>{{ notice.message }}
                        </span>
                        <span class="mt-0.5 block text-xs text-muted">
                            <span v-if="notice.actorName">{{ notice.actorName }} · </span>{{ notice.createdAtLabel }}
                        </span>
                    </span>
                    <span v-if="notice.hasLink" class="mt-0.5 shrink-0 text-sm text-sea-700" aria-hidden="true">→</span>
                </Link>
            </li>
            <li v-if="notices.data.length === 0" class="px-4 py-6 text-sm text-muted">
                {{ filter === 'unread' ? 'Непрочитанных уведомлений нет.' : 'Уведомлений пока нет. Они появятся, когда в CRM что-то изменится.' }}
            </li>
        </ul>

        <nav v-if="notices.lastPage > 1" class="mt-4 flex max-w-3xl items-center justify-end gap-2 text-sm text-muted" aria-label="Страницы уведомлений">
            <Link
                v-if="notices.previousPageUrl"
                :href="notices.previousPageUrl"
                class="rounded-md border border-line bg-white px-3 py-1.5 text-ink hover:bg-surface"
            >
                ← Назад
            </Link>
            <span>Страница {{ notices.currentPage }} из {{ notices.lastPage }}</span>
            <Link
                v-if="notices.nextPageUrl"
                :href="notices.nextPageUrl"
                class="rounded-md border border-line bg-white px-3 py-1.5 text-ink hover:bg-surface"
            >
                Вперёд →
            </Link>
        </nav>
    </AppLayout>
</template>

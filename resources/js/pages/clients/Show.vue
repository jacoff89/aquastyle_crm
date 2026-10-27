<script setup>
import { Link, router } from '@inertiajs/vue3';
import ClientBookings from '../../components/ClientBookings.vue';
import AppLayout from '../../layouts/AppLayout.vue';

const props = defineProps({
    client: { type: Object, required: true },
    canDelete: { type: Boolean, required: true },
    upcoming: { type: Array, required: true },
    history: { type: Array, required: true },
    historyTotal: { type: Number, required: true },
});

const destroy = () => {
    if (window.confirm(`Удалить клиента «${props.client.fullName}»? История его занятий сохранится.`)) {
        router.delete(`/clients/${props.client.id}`);
    }
};
</script>

<template>
    <AppLayout :title="client.fullName">
        <template #actions>
            <div class="flex items-center gap-3">
                <button
                    v-if="canDelete"
                    type="button"
                    class="inline-flex items-center rounded-md px-3 py-2 text-sm font-medium text-flag transition-colors hover:bg-red-50"
                    @click="destroy"
                >
                    Удалить
                </button>
                <Link
                    :href="`/clients/${client.id}/edit`"
                    class="inline-flex items-center rounded-md border border-line bg-white px-4 py-2 text-sm font-medium text-ink transition-colors hover:bg-surface"
                >
                    Редактировать
                </Link>
            </div>
        </template>

        <div class="max-w-2xl space-y-8">
            <section class="rounded-lg border border-line bg-white p-6" aria-labelledby="contacts-heading">
                <h2 id="contacts-heading" class="text-lg font-semibold">Контакты</h2>

                <dl class="mt-4 grid gap-x-6 gap-y-4 text-sm sm:grid-cols-2">
                    <div>
                        <dt class="text-muted">Телефон</dt>
                        <dd class="mt-0.5 text-ink">{{ client.phone }}</dd>
                    </div>
                    <div>
                        <dt class="text-muted">Email</dt>
                        <dd class="mt-0.5 text-ink">{{ client.email || '—' }}</dd>
                    </div>
                    <div>
                        <dt class="text-muted">Дата рождения</dt>
                        <dd class="mt-0.5 text-ink">{{ client.birthDateLabel || '—' }}</dd>
                    </div>
                    <div v-if="client.notes" class="sm:col-span-2">
                        <dt class="text-muted">Заметки</dt>
                        <dd class="mt-0.5 whitespace-pre-line text-ink">{{ client.notes }}</dd>
                    </div>
                </dl>
            </section>

            <section aria-labelledby="upcoming-heading">
                <h2 id="upcoming-heading" class="text-lg font-semibold">Ближайшие занятия</h2>
                <div class="mt-3">
                    <ClientBookings
                        :rows="upcoming"
                        label="Ближайшие занятия клиента"
                        empty-title="Занятий пока нет"
                        empty-text="Записать клиента можно в календаре: откройте занятие и перейдите на вкладку «Клиенты»."
                    />
                </div>
            </section>

            <section aria-labelledby="history-heading">
                <h2 id="history-heading" class="text-lg font-semibold">История посещений</h2>
                <div class="mt-3">
                    <ClientBookings
                        :rows="history"
                        label="История посещений клиента"
                        empty-title="Посещений пока нет"
                        empty-text="Здесь будут занятия, на которые клиент приходил или не пришёл."
                    />
                </div>
                <p v-if="historyTotal > history.length" class="mt-2 text-sm text-muted">
                    Показаны последние {{ history.length }} из {{ historyTotal }}.
                </p>
            </section>

            <Link href="/clients" class="inline-block text-sm text-muted hover:text-ink">← Все клиенты</Link>
        </div>
    </AppLayout>
</template>

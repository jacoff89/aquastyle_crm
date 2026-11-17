<script setup>
import ReferenceList from '../../../components/ReferenceList.vue';
import AppLayout from '../../../layouts/AppLayout.vue';

defineProps({
    clientStatuses: { type: Array, required: true },
});
</script>

<template>
    <AppLayout title="Статусы клиентов">
        <p class="max-w-2xl text-sm leading-6 text-muted">
            Статус показывает, на каком этапе обучения клиент: например, «Проходит курс закрытой воды» или «Ждёт сертификат». У клиента может быть один статус, его
            выбирают в карточке клиента. В этом порядке статусы предлагаются при выборе. Скрытый статус остаётся у клиентов, у которых он уже стоит, но выбрать его
            заново нельзя.
        </p>

        <ReferenceList
            class="mt-6"
            :items="clientStatuses"
            url="/settings/client-statuses"
            item-label="статуса"
            hidden-label="скрыт"
            add-label="Добавить статус"
            placeholder="Например, «Ждёт сертификат»"
            empty-text="Статусов пока нет. Добавьте первый, чтобы отмечать, на каком этапе клиент."
        />
    </AppLayout>
</template>

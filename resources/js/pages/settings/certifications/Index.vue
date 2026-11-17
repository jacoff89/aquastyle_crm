<script setup>
import ReferenceList from '../../../components/ReferenceList.vue';
import AppLayout from '../../../layouts/AppLayout.vue';

defineProps({
    certifications: { type: Array, required: true },
});
</script>

<template>
    <AppLayout title="Сертификации">
        <p class="max-w-2xl text-sm leading-6 text-muted">
            Сертификации, которые есть у клиента: например, «Дайвер» или «Сухой костюм». У клиента их может быть сколько угодно, отмечают их в карточке клиента. В этом
            порядке сертификации предлагаются при выборе и показываются у клиента. Скрытая сертификация остаётся у клиентов, у которых она уже есть, но выбрать её
            заново нельзя.
        </p>

        <ReferenceList
            class="mt-6"
            :items="certifications"
            url="/settings/certifications"
            item-label="сертификации"
            hidden-label="скрыта"
            add-label="Добавить сертификацию"
            placeholder="Например, «Сухой костюм»"
            empty-text="Сертификаций пока нет. Добавьте первую, чтобы отмечать их у клиентов."
        />
    </AppLayout>
</template>

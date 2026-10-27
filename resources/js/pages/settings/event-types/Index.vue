<script setup>
import { router, useForm } from '@inertiajs/vue3';
import { nextTick, ref } from 'vue';
import AppIcon from '../../../components/AppIcon.vue';
import PrimaryButton from '../../../components/PrimaryButton.vue';
import TextInput from '../../../components/TextInput.vue';
import AppLayout from '../../../layouts/AppLayout.vue';

defineProps({
    eventTypes: { type: Array, required: true },
});

const url = (eventType) => `/settings/event-types/${eventType.id}`;

const addForm = useForm({ name: '' });

const add = () => {
    addForm.post('/settings/event-types', {
        preserveScroll: true,
        onSuccess: () => addForm.reset(),
    });
};

const editingId = ref(null);
const editForm = useForm({ name: '' });

const startEditing = async (eventType) => {
    editingId.value = eventType.id;
    editForm.clearErrors();
    editForm.name = eventType.name;
    await nextTick();
    document.getElementById(`type-name-${eventType.id}`)?.focus();
};

const stopEditing = () => {
    editingId.value = null;
    editForm.clearErrors();
};

const rename = (eventType) => {
    editForm.patch(url(eventType), {
        preserveScroll: true,
        onSuccess: stopEditing,
    });
};

const toggle = (eventType) => {
    router.patch(url(eventType), { is_active: !eventType.isActive }, { preserveScroll: true });
};

const move = (eventType, direction) => {
    router.patch(`${url(eventType)}/position`, { direction }, { preserveScroll: true });
};
</script>

<template>
    <AppLayout title="Типы занятий">
        <p class="max-w-2xl text-sm leading-6 text-muted">
            В этом порядке типы предлагаются при создании занятия. Скрытый тип остаётся у прошлых занятий, но для новых
            его выбрать нельзя.
        </p>

        <ul class="mt-6 max-w-2xl divide-y divide-line rounded-lg border border-line bg-white">
            <li
                v-for="(eventType, index) in eventTypes"
                :key="eventType.id"
                class="flex items-center gap-3 px-3 py-2.5 sm:px-4"
            >
                <div class="flex shrink-0 flex-col" aria-label="Порядок">
                    <button
                        type="button"
                        class="rounded p-0.5 text-muted hover:bg-sea-50 hover:text-sea-700 disabled:invisible"
                        :disabled="index === 0"
                        :aria-label="`Поднять «${eventType.name}» выше`"
                        @click="move(eventType, 'up')"
                    >
                        <AppIcon name="up" />
                    </button>
                    <button
                        type="button"
                        class="rounded p-0.5 text-muted hover:bg-sea-50 hover:text-sea-700 disabled:invisible"
                        :disabled="index === eventTypes.length - 1"
                        :aria-label="`Опустить «${eventType.name}» ниже`"
                        @click="move(eventType, 'down')"
                    >
                        <AppIcon name="down" />
                    </button>
                </div>

                <form
                    v-if="editingId === eventType.id"
                    class="flex min-w-0 flex-1 flex-wrap items-start gap-2"
                    novalidate
                    @submit.prevent="rename(eventType)"
                    @keydown.esc="stopEditing"
                >
                    <div class="min-w-48 flex-1">
                        <label :for="`type-name-${eventType.id}`" class="sr-only">Название типа</label>
                        <TextInput
                            :id="`type-name-${eventType.id}`"
                            v-model="editForm.name"
                            required
                            :invalid="Boolean(editForm.errors.name)"
                        />
                        <p v-if="editForm.errors.name" class="mt-1 text-sm text-flag">{{ editForm.errors.name }}</p>
                    </div>
                    <PrimaryButton :processing="editForm.processing">Сохранить</PrimaryButton>
                    <button type="button" class="px-2 py-2 text-sm text-muted hover:text-ink" @click="stopEditing">
                        Отмена
                    </button>
                </form>

                <div v-else class="flex min-w-0 flex-1 flex-col gap-1 sm:flex-row sm:items-center sm:gap-3">
                    <div class="flex min-w-0 flex-1 items-center gap-2">
                        <span class="truncate" :class="eventType.isActive ? 'text-ink' : 'text-muted line-through'">
                            {{ eventType.name }}
                        </span>
                        <span v-if="!eventType.isActive" class="shrink-0 rounded bg-slate-100 px-2 py-0.5 text-xs text-muted">скрыт</span>
                    </div>
                    <div class="-ml-2 flex shrink-0 gap-1 sm:ml-0">
                        <button
                            type="button"
                            class="rounded px-2 py-1 text-sm text-sea-700 hover:bg-sea-50"
                            @click="startEditing(eventType)"
                        >
                            Переименовать
                        </button>
                        <button
                            type="button"
                            class="rounded px-2 py-1 text-sm text-sea-700 hover:bg-sea-50"
                            @click="toggle(eventType)"
                        >
                            {{ eventType.isActive ? 'Скрыть' : 'Вернуть' }}
                        </button>
                    </div>
                </div>
            </li>
            <li v-if="eventTypes.length === 0" class="px-4 py-6 text-sm text-muted">
                Типов пока нет. Добавьте первый, чтобы создавать занятия.
            </li>
        </ul>

        <form class="mt-6 flex max-w-2xl flex-wrap items-start gap-3" novalidate @submit.prevent="add">
            <div class="min-w-56 flex-1">
                <label for="new-type" class="sr-only">Название нового типа</label>
                <TextInput
                    id="new-type"
                    v-model="addForm.name"
                    placeholder="Например, «Спасательный курс»"
                    required
                    :invalid="Boolean(addForm.errors.name)"
                />
                <p v-if="addForm.errors.name" class="mt-1 text-sm text-flag">{{ addForm.errors.name }}</p>
            </div>
            <PrimaryButton :processing="addForm.processing">
                <AppIcon name="plus" />
                <span class="ml-1.5">Добавить тип</span>
            </PrimaryButton>
        </form>
    </AppLayout>
</template>

<script setup>
import { router, useForm } from '@inertiajs/vue3';
import { nextTick, ref } from 'vue';
import AppIcon from './AppIcon.vue';
import PrimaryButton from './PrimaryButton.vue';
import TextInput from './TextInput.vue';

/**
 * Простой справочник в настройках: добавить, переименовать, скрыть или вернуть, поменять порядок.
 * Элемент: { id, name, isActive, clientsCount }.
 */
const props = defineProps({
    items: { type: Array, required: true },
    /** Адрес списка, например «/settings/certifications». */
    url: { type: String, required: true },
    /** Как назвать элемент в подписях для экранного диктора: «статуса», «сертификации». */
    itemLabel: { type: String, required: true },
    hiddenLabel: { type: String, required: true },
    addLabel: { type: String, required: true },
    placeholder: { type: String, required: true },
    emptyText: { type: String, required: true },
});

const isFirst = (item) => props.items[0].id === item.id;
const isLast = (item) => props.items.at(-1).id === item.id;

const itemUrl = (item) => `${props.url}/${item.id}`;

/** «у 1 клиента», «у 21 клиента», но «у 11 клиентов», «у 5 клиентов». */
const clientsLabel = (count) => {
    if (count === 0) {
        return 'нет клиентов';
    }

    const word = count % 10 === 1 && count % 100 !== 11 ? 'клиента' : 'клиентов';

    return `у ${count} ${word}`;
};

const addForm = useForm({ name: '' });

const add = () => {
    addForm.post(props.url, {
        preserveScroll: true,
        onSuccess: () => addForm.reset('name'),
    });
};

const editingId = ref(null);
const editForm = useForm({ name: '' });

const startEditing = async (item) => {
    editingId.value = item.id;
    editForm.clearErrors();
    editForm.name = item.name;
    await nextTick();
    document.getElementById(`reference-name-${item.id}`)?.focus();
};

const stopEditing = () => {
    editingId.value = null;
    editForm.clearErrors();
};

const rename = (item) => {
    editForm.patch(itemUrl(item), {
        preserveScroll: true,
        onSuccess: stopEditing,
    });
};

const toggle = (item) => {
    router.patch(itemUrl(item), { is_active: !item.isActive }, { preserveScroll: true });
};

const move = (item, direction) => {
    router.patch(`${itemUrl(item)}/position`, { direction }, { preserveScroll: true });
};
</script>

<template>
    <div>
        <ul class="max-w-2xl divide-y divide-line rounded-lg border border-line bg-white">
            <li v-for="item in items" :key="item.id" class="flex items-center gap-3 px-3 py-2.5 sm:px-4">
                <div class="flex shrink-0 flex-col" aria-label="Порядок">
                    <button
                        type="button"
                        class="rounded p-0.5 text-muted hover:bg-sea-50 hover:text-sea-700 disabled:invisible"
                        :disabled="isFirst(item)"
                        :aria-label="`Поднять «${item.name}» выше`"
                        @click="move(item, 'up')"
                    >
                        <AppIcon name="up" />
                    </button>
                    <button
                        type="button"
                        class="rounded p-0.5 text-muted hover:bg-sea-50 hover:text-sea-700 disabled:invisible"
                        :disabled="isLast(item)"
                        :aria-label="`Опустить «${item.name}» ниже`"
                        @click="move(item, 'down')"
                    >
                        <AppIcon name="down" />
                    </button>
                </div>

                <form
                    v-if="editingId === item.id"
                    class="flex min-w-0 flex-1 flex-wrap items-start gap-2"
                    novalidate
                    @submit.prevent="rename(item)"
                    @keydown.esc="stopEditing"
                >
                    <div class="min-w-48 flex-1">
                        <label :for="`reference-name-${item.id}`" class="sr-only">Название {{ itemLabel }}</label>
                        <TextInput :id="`reference-name-${item.id}`" v-model="editForm.name" required :invalid="Boolean(editForm.errors.name)" />
                        <p v-if="editForm.errors.name" class="mt-1 text-sm text-flag">{{ editForm.errors.name }}</p>
                    </div>
                    <PrimaryButton :processing="editForm.processing">Сохранить</PrimaryButton>
                    <button type="button" class="px-2 py-2 text-sm text-muted hover:text-ink" @click="stopEditing">Отмена</button>
                </form>

                <div v-else class="flex min-w-0 flex-1 flex-col gap-1 sm:flex-row sm:items-center sm:gap-3">
                    <div class="flex min-w-0 flex-1 items-center gap-2">
                        <span class="truncate" :class="item.isActive ? 'text-ink' : 'text-muted line-through'">{{ item.name }}</span>
                        <span v-if="!item.isActive" class="shrink-0 rounded bg-slate-100 px-2 py-0.5 text-xs text-muted">{{ hiddenLabel }}</span>
                        <span class="shrink-0 text-xs text-muted">{{ clientsLabel(item.clientsCount) }}</span>
                    </div>
                    <div class="-ml-2 flex shrink-0 flex-wrap gap-1 sm:ml-0">
                        <button type="button" class="rounded px-2 py-1 text-sm text-sea-700 hover:bg-sea-50" @click="startEditing(item)">Изменить</button>
                        <button type="button" class="rounded px-2 py-1 text-sm text-sea-700 hover:bg-sea-50" @click="toggle(item)">
                            {{ item.isActive ? 'Скрыть' : 'Вернуть' }}
                        </button>
                    </div>
                </div>
            </li>
            <li v-if="items.length === 0" class="px-4 py-6 text-sm text-muted">{{ emptyText }}</li>
        </ul>

        <form class="mt-6 flex max-w-2xl flex-wrap items-start gap-3" novalidate @submit.prevent="add">
            <div class="min-w-56 flex-1">
                <label for="new-reference" class="sr-only">Название нового {{ itemLabel }}</label>
                <TextInput id="new-reference" v-model="addForm.name" :placeholder="placeholder" required :invalid="Boolean(addForm.errors.name)" />
                <p v-if="addForm.errors.name" class="mt-1 text-sm text-flag">{{ addForm.errors.name }}</p>
            </div>
            <PrimaryButton :processing="addForm.processing">
                <AppIcon name="plus" />
                <span class="ml-1.5">{{ addLabel }}</span>
            </PrimaryButton>
        </form>
    </div>
</template>

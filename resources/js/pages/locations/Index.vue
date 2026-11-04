<script setup>
import { Link, router, useForm } from '@inertiajs/vue3';
import { nextTick, ref } from 'vue';
import AppIcon from '../../components/AppIcon.vue';
import PrimaryButton from '../../components/PrimaryButton.vue';
import TextInput from '../../components/TextInput.vue';
import AppLayout from '../../layouts/AppLayout.vue';

defineProps({
    /** Локации: { id, name, address, isActive, equipmentCount }. */
    locations: { type: Array, required: true },
});

const url = (location) => `/locations/${location.id}`;

const addForm = useForm({ name: '', address: '' });

const add = () => {
    addForm.post('/locations', {
        preserveScroll: true,
        onSuccess: () => addForm.reset(),
    });
};

const editingId = ref(null);
const editForm = useForm({ name: '', address: '' });

const startEditing = async (location) => {
    editingId.value = location.id;
    editForm.clearErrors();
    editForm.name = location.name;
    editForm.address = location.address ?? '';
    await nextTick();
    document.getElementById(`location-name-${location.id}`)?.focus();
};

const stopEditing = () => {
    editingId.value = null;
    editForm.clearErrors();
};

const save = (location) => {
    editForm.patch(url(location), {
        preserveScroll: true,
        onSuccess: stopEditing,
    });
};

const toggle = (location) => {
    router.patch(url(location), { is_active: !location.isActive }, { preserveScroll: true });
};
</script>

<template>
    <AppLayout title="Локации">
        <p class="max-w-2xl text-sm leading-6 text-muted">
            Локации предлагаются в поле «Место» при создании и правке занятия; при этом место можно вписать и вручную. К локации
            привязывается снаряжение, которое там хранится. Скрытая локация больше не предлагается в занятиях, но снаряжение
            остаётся за ней.
        </p>

        <ul class="mt-6 max-w-2xl divide-y divide-line rounded-lg border border-line bg-white">
            <li v-for="location in locations" :key="location.id" class="px-3 py-2.5 sm:px-4">
                <form
                    v-if="editingId === location.id"
                    class="flex flex-wrap items-start gap-2"
                    novalidate
                    @submit.prevent="save(location)"
                    @keydown.esc="stopEditing"
                >
                    <div class="min-w-48 flex-1 space-y-2">
                        <div>
                            <label :for="`location-name-${location.id}`" class="sr-only">Название локации</label>
                            <TextInput
                                :id="`location-name-${location.id}`"
                                v-model="editForm.name"
                                placeholder="Название"
                                required
                                :invalid="Boolean(editForm.errors.name)"
                            />
                            <p v-if="editForm.errors.name" class="mt-1 text-sm text-flag">{{ editForm.errors.name }}</p>
                        </div>
                        <div>
                            <label :for="`location-address-${location.id}`" class="sr-only">Адрес локации</label>
                            <TextInput
                                :id="`location-address-${location.id}`"
                                v-model="editForm.address"
                                placeholder="Адрес (необязательно)"
                                :invalid="Boolean(editForm.errors.address)"
                            />
                            <p v-if="editForm.errors.address" class="mt-1 text-sm text-flag">{{ editForm.errors.address }}</p>
                        </div>
                    </div>
                    <PrimaryButton :processing="editForm.processing">Сохранить</PrimaryButton>
                    <button type="button" class="px-2 py-2 text-sm text-muted hover:text-ink" @click="stopEditing">Отмена</button>
                </form>

                <div v-else class="flex flex-col gap-1 sm:flex-row sm:items-center sm:gap-3">
                    <div class="min-w-0 flex-1">
                        <div class="flex items-center gap-2">
                            <span class="truncate" :class="location.isActive ? 'text-ink' : 'text-muted line-through'">
                                {{ location.name }}
                            </span>
                            <span v-if="!location.isActive" class="shrink-0 rounded bg-slate-100 px-2 py-0.5 text-xs text-muted">скрыта</span>
                        </div>
                        <p class="mt-0.5 text-xs text-muted">
                            <span v-if="location.address">{{ location.address }} · </span>
                            <Link
                                v-if="location.equipmentCount"
                                :href="`/equipment?location=${location.id}`"
                                class="underline-offset-4 hover:text-sea-700 hover:underline"
                            >
                                снаряжение: {{ location.equipmentCount }}
                            </Link>
                            <span v-else>снаряжения нет</span>
                        </p>
                    </div>
                    <div class="-ml-2 flex shrink-0 flex-wrap gap-1 sm:ml-0">
                        <button type="button" class="rounded px-2 py-1 text-sm text-sea-700 hover:bg-sea-50" @click="startEditing(location)">
                            Изменить
                        </button>
                        <button type="button" class="rounded px-2 py-1 text-sm text-sea-700 hover:bg-sea-50" @click="toggle(location)">
                            {{ location.isActive ? 'Скрыть' : 'Вернуть' }}
                        </button>
                    </div>
                </div>
            </li>
            <li v-if="locations.length === 0" class="px-4 py-6 text-sm text-muted">
                Локаций пока нет. Добавьте первую, чтобы выбирать её в занятиях и привязывать к ней снаряжение.
            </li>
        </ul>

        <form class="mt-6 flex max-w-2xl flex-wrap items-start gap-3" novalidate @submit.prevent="add">
            <div class="min-w-48 flex-1">
                <label for="new-location" class="sr-only">Название новой локации</label>
                <TextInput
                    id="new-location"
                    v-model="addForm.name"
                    placeholder="Например, «Бассейн „Дельфин“»"
                    required
                    :invalid="Boolean(addForm.errors.name)"
                />
                <p v-if="addForm.errors.name" class="mt-1 text-sm text-flag">{{ addForm.errors.name }}</p>
            </div>
            <div class="min-w-48 flex-1">
                <label for="new-location-address" class="sr-only">Адрес новой локации</label>
                <TextInput
                    id="new-location-address"
                    v-model="addForm.address"
                    placeholder="Адрес (необязательно)"
                    :invalid="Boolean(addForm.errors.address)"
                />
                <p v-if="addForm.errors.address" class="mt-1 text-sm text-flag">{{ addForm.errors.address }}</p>
            </div>
            <PrimaryButton :processing="addForm.processing">
                <AppIcon name="plus" />
                <span class="ml-1.5">Добавить локацию</span>
            </PrimaryButton>
        </form>
    </AppLayout>
</template>

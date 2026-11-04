<script setup>
import { router, useForm } from '@inertiajs/vue3';
import { nextTick, ref } from 'vue';
import AppIcon from '../../../components/AppIcon.vue';
import PrimaryButton from '../../../components/PrimaryButton.vue';
import TextInput from '../../../components/TextInput.vue';
import AppLayout from '../../../layouts/AppLayout.vue';

const props = defineProps({
    exercises: { type: Array, required: true },
    /** Типы занятий в порядке дерева: { id, parentId, name, isActive }. */
    eventTypes: { type: Array, required: true },
});

const typeName = (eventType) => {
    const parent = props.eventTypes.find((other) => other.id === eventType.parentId);

    return parent ? `${parent.name} / ${eventType.name}` : eventType.name;
};

const exerciseTypes = (exercise) => props.eventTypes.filter((eventType) => exercise.eventTypeIds.includes(eventType.id));

const isFirst = (exercise) => props.exercises[0].id === exercise.id;
const isLast = (exercise) => props.exercises.at(-1).id === exercise.id;

const url = (exercise) => `/settings/exercises/${exercise.id}`;

const addForm = useForm({ name: '' });

const add = () => {
    addForm.post('/settings/exercises', {
        preserveScroll: true,
        onSuccess: () => addForm.reset('name'),
    });
};

const editingId = ref(null);
const editForm = useForm({ name: '' });

const startEditing = async (exercise) => {
    typesEditingId.value = null;
    editingId.value = exercise.id;
    editForm.clearErrors();
    editForm.name = exercise.name;
    await nextTick();
    document.getElementById(`exercise-name-${exercise.id}`)?.focus();
};

const stopEditing = () => {
    editingId.value = null;
    editForm.clearErrors();
};

const rename = (exercise) => {
    editForm.patch(url(exercise), {
        preserveScroll: true,
        onSuccess: stopEditing,
    });
};

const toggle = (exercise) => {
    router.patch(url(exercise), { is_active: !exercise.isActive }, { preserveScroll: true });
};

const typesEditingId = ref(null);
const typesForm = useForm({ event_type_ids: [] });

const startTypes = (exercise) => {
    stopEditing();
    typesEditingId.value = exercise.id;
    typesForm.clearErrors();
    typesForm.event_type_ids = [...exercise.eventTypeIds];
};

const stopTypes = () => {
    typesEditingId.value = null;
    typesForm.clearErrors();
};

/** Дочерний тип с выбранным родителем выбирать не нужно: упражнения родителя предлагаются и в нём. */
const isCoveredByParent = (eventType) => eventType.parentId !== null && typesForm.event_type_ids.includes(eventType.parentId);

const saveTypes = (exercise) => {
    typesForm.patch(url(exercise), {
        preserveScroll: true,
        onSuccess: stopTypes,
    });
};

const move = (exercise, direction) => {
    router.patch(`${url(exercise)}/position`, { direction }, { preserveScroll: true });
};
</script>

<template>
    <AppLayout title="Упражнения">
        <p class="max-w-2xl text-sm leading-6 text-muted">
            Упражнения можно прикреплять к клиенту на занятии: откройте занятие в календаре, вкладка «Клиенты». В этом порядке они предлагаются при выборе. Занятию
            предлагаются только упражнения его типа; упражнение родительского типа предлагается и во всех дочерних. Скрытое упражнение остаётся у клиентов, которым оно
            уже назначено, но выбрать его заново нельзя.
        </p>

        <ul class="mt-6 max-w-2xl divide-y divide-line rounded-lg border border-line bg-white">
            <li v-for="exercise in exercises" :key="exercise.id" class="flex items-center gap-3 px-3 py-2.5 sm:px-4">
                <div class="flex shrink-0 flex-col" aria-label="Порядок">
                    <button
                        type="button"
                        class="rounded p-0.5 text-muted hover:bg-sea-50 hover:text-sea-700 disabled:invisible"
                        :disabled="isFirst(exercise)"
                        :aria-label="`Поднять «${exercise.name}» выше`"
                        @click="move(exercise, 'up')"
                    >
                        <AppIcon name="up" />
                    </button>
                    <button
                        type="button"
                        class="rounded p-0.5 text-muted hover:bg-sea-50 hover:text-sea-700 disabled:invisible"
                        :disabled="isLast(exercise)"
                        :aria-label="`Опустить «${exercise.name}» ниже`"
                        @click="move(exercise, 'down')"
                    >
                        <AppIcon name="down" />
                    </button>
                </div>

                <form
                    v-if="editingId === exercise.id"
                    class="flex min-w-0 flex-1 flex-wrap items-start gap-2"
                    novalidate
                    @submit.prevent="rename(exercise)"
                    @keydown.esc="stopEditing"
                >
                    <div class="min-w-48 flex-1">
                        <label :for="`exercise-name-${exercise.id}`" class="sr-only">Название упражнения</label>
                        <TextInput
                            :id="`exercise-name-${exercise.id}`"
                            v-model="editForm.name"
                            required
                            :invalid="Boolean(editForm.errors.name)"
                        />
                        <p v-if="editForm.errors.name" class="mt-1 text-sm text-flag">{{ editForm.errors.name }}</p>
                    </div>
                    <PrimaryButton :processing="editForm.processing">Сохранить</PrimaryButton>
                    <button type="button" class="px-2 py-2 text-sm text-muted hover:text-ink" @click="stopEditing">Отмена</button>
                </form>

                <div v-else class="min-w-0 flex-1">
                    <div class="flex flex-col gap-1 sm:flex-row sm:items-center sm:gap-3">
                        <div class="flex min-w-0 flex-1 items-center gap-2">
                            <span class="truncate" :class="exercise.isActive ? 'text-ink' : 'text-muted line-through'">
                                {{ exercise.name }}
                            </span>
                            <span v-if="!exercise.isActive" class="shrink-0 rounded bg-slate-100 px-2 py-0.5 text-xs text-muted">скрыто</span>
                        </div>
                        <div class="-ml-2 flex shrink-0 flex-wrap gap-1 sm:ml-0">
                            <button type="button" class="rounded px-2 py-1 text-sm text-sea-700 hover:bg-sea-50" @click="startEditing(exercise)">
                                Изменить
                            </button>
                            <button type="button" class="rounded px-2 py-1 text-sm text-sea-700 hover:bg-sea-50" @click="startTypes(exercise)">
                                Типы занятий
                            </button>
                            <button type="button" class="rounded px-2 py-1 text-sm text-sea-700 hover:bg-sea-50" @click="toggle(exercise)">
                                {{ exercise.isActive ? 'Скрыть' : 'Вернуть' }}
                            </button>
                        </div>
                    </div>

                    <form v-if="typesEditingId === exercise.id" class="mt-2 space-y-2" novalidate @submit.prevent="saveTypes(exercise)" @keydown.esc="stopTypes">
                        <fieldset>
                            <legend class="text-sm text-muted">Для каких занятий предлагать упражнение</legend>
                            <p v-if="!eventTypes.length" class="mt-1 text-sm text-muted">Типов занятий пока нет.</p>
                            <label
                                v-for="eventType in eventTypes"
                                :key="eventType.id"
                                class="mt-1 flex items-start gap-2 text-sm"
                                :class="[eventType.parentId !== null ? 'pl-6' : '', eventType.isActive ? 'text-ink' : 'text-muted']"
                            >
                                <input
                                    v-model="typesForm.event_type_ids"
                                    type="checkbox"
                                    :value="eventType.id"
                                    class="mt-0.5 size-4 rounded border-line accent-sea-600"
                                />
                                <span>
                                    {{ eventType.name }}
                                    <span v-if="!eventType.isActive" class="ml-1 rounded bg-slate-100 px-1.5 py-0.5 text-xs text-muted">скрыт</span>
                                    <span v-if="isCoveredByParent(eventType)" class="ml-1 text-xs text-muted">уже входит через родительский тип</span>
                                </span>
                            </label>
                        </fieldset>
                        <p v-if="typesForm.errors.event_type_ids" class="text-sm text-flag">{{ typesForm.errors.event_type_ids }}</p>
                        <div class="flex items-center gap-2">
                            <PrimaryButton :processing="typesForm.processing">Сохранить</PrimaryButton>
                            <button type="button" class="px-2 py-2 text-sm text-muted hover:text-ink" @click="stopTypes">Отмена</button>
                        </div>
                    </form>

                    <ul v-else-if="exerciseTypes(exercise).length" class="mt-1.5 flex flex-wrap gap-1.5" aria-label="Типы занятий">
                        <li v-for="eventType in exerciseTypes(exercise)" :key="eventType.id" class="rounded-full bg-sea-50 px-2.5 py-0.5 text-xs font-medium text-sea-700">
                            {{ typeName(eventType) }}
                        </li>
                    </ul>
                    <p v-else class="mt-1 text-xs text-flag">Не привязано к типам занятий — в календаре не предлагается.</p>
                </div>
            </li>
            <li v-if="exercises.length === 0" class="px-4 py-6 text-sm text-muted">
                Упражнений пока нет. Добавьте первое, чтобы прикреплять его к клиентам.
            </li>
        </ul>

        <form class="mt-6 flex max-w-2xl flex-wrap items-start gap-3" novalidate @submit.prevent="add">
            <div class="min-w-56 flex-1">
                <label for="new-exercise" class="sr-only">Название нового упражнения</label>
                <TextInput
                    id="new-exercise"
                    v-model="addForm.name"
                    placeholder="Например, «Снятие и надевание маски»"
                    required
                    :invalid="Boolean(addForm.errors.name)"
                />
                <p v-if="addForm.errors.name" class="mt-1 text-sm text-flag">{{ addForm.errors.name }}</p>
            </div>
            <PrimaryButton :processing="addForm.processing">
                <AppIcon name="plus" />
                <span class="ml-1.5">Добавить упражнение</span>
            </PrimaryButton>
        </form>
    </AppLayout>
</template>

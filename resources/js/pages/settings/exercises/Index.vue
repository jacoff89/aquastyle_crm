<script setup>
import { router, useForm } from '@inertiajs/vue3';
import { nextTick, ref } from 'vue';
import AppIcon from '../../../components/AppIcon.vue';
import PrimaryButton from '../../../components/PrimaryButton.vue';
import TextInput from '../../../components/TextInput.vue';
import AppLayout from '../../../layouts/AppLayout.vue';

const props = defineProps({
    exercises: { type: Array, required: true },
});

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

const move = (exercise, direction) => {
    router.patch(`${url(exercise)}/position`, { direction }, { preserveScroll: true });
};
</script>

<template>
    <AppLayout title="Упражнения">
        <p class="max-w-2xl text-sm leading-6 text-muted">
            Упражнения можно прикреплять к клиенту на занятии: откройте занятие в календаре, вкладка «Клиенты». В этом порядке они предлагаются при выборе. Скрытое упражнение остаётся у клиентов,
            которым оно уже назначено, но выбрать его заново нельзя.
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

                <div v-else class="flex min-w-0 flex-1 flex-col gap-1 sm:flex-row sm:items-center sm:gap-3">
                    <div class="flex min-w-0 flex-1 items-center gap-2">
                        <span class="truncate" :class="exercise.isActive ? 'text-ink' : 'text-muted line-through'">
                            {{ exercise.name }}
                        </span>
                        <span v-if="!exercise.isActive" class="shrink-0 rounded bg-slate-100 px-2 py-0.5 text-xs text-muted">скрыто</span>
                    </div>
                    <div class="-ml-2 flex shrink-0 gap-1 sm:ml-0">
                        <button type="button" class="rounded px-2 py-1 text-sm text-sea-700 hover:bg-sea-50" @click="startEditing(exercise)">
                            Изменить
                        </button>
                        <button type="button" class="rounded px-2 py-1 text-sm text-sea-700 hover:bg-sea-50" @click="toggle(exercise)">
                            {{ exercise.isActive ? 'Скрыть' : 'Вернуть' }}
                        </button>
                    </div>
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

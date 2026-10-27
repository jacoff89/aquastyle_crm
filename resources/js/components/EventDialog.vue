<script setup>
import { useHttp } from '@inertiajs/vue3';
import { computed, nextTick, onMounted, ref, watch } from 'vue';
import AppIcon from './AppIcon.vue';
import EventClientsPanel from './EventClientsPanel.vue';
import FormField from './FormField.vue';
import PrimaryButton from './PrimaryButton.vue';
import SelectInput from './SelectInput.vue';
import TextArea from './TextArea.vue';
import TextInput from './TextInput.vue';

const props = defineProps({
    /** Занятие для правки или null для нового. */
    event: { type: Object, default: null },
    /** Начальные значения нового занятия: { start, end, leadInstructorId }. */
    draft: { type: Object, default: () => ({}) },
    instructors: { type: Array, required: true },
    eventTypes: { type: Array, required: true },
    statuses: { type: Array, required: true },
    attendanceStatuses: { type: Array, required: true },
    /** Запрос к серверу страницы календаря: отвечает { status, data }, ответы 4xx — обычный результат. */
    request: { type: Function, required: true },
});

const emit = defineEmits(['saved', 'close']);

const isEditing = computed(() => props.event !== null);

const splitDateTime = (value) => {
    const [date = '', time = ''] = (value ?? '').split(' ');

    return { date, time };
};

const start = splitDateTime(props.event?.start ?? props.draft.start);
const end = splitDateTime(props.event?.end ?? props.draft.end);

const firstActiveType = props.eventTypes.find((eventType) => eventType.isActive);

const form = useHttp({
    event_type_id: props.event?.eventTypeId ?? firstActiveType?.id ?? '',
    title: props.event?.customTitle ?? '',
    date: start.date,
    start_time: start.time,
    end_time: end.time,
    location: props.event?.location ?? '',
    capacity: props.event?.capacity == null ? '' : String(props.event.capacity),
    lead_instructor_id: props.event?.leadInstructorId ?? props.draft.leadInstructorId ?? '',
    assistant_ids: [...(props.event?.assistantIds ?? [])],
    status: props.event?.status ?? 'planned',
    notes: props.event?.notes ?? '',
    confirm_conflicts: false,
});

/**
 * Дата следующего дня в виде YYYY-MM-DD: занятие, которое кончается раньше, чем началось,
 * переходит через полночь (например, ночное погружение).
 */
const nextDay = (date) => {
    const [year, month, day] = date.split('-').map(Number);
    const next = new Date(year, month - 1, day + 1);

    return [next.getFullYear(), String(next.getMonth() + 1).padStart(2, '0'), String(next.getDate()).padStart(2, '0')].join('-');
};

const endsNextDay = computed(() => Boolean(form.start_time && form.end_time && form.end_time <= form.start_time));

form.transform((data) => ({
    event_type_id: data.event_type_id,
    title: data.title,
    starts_at: `${data.date} ${data.start_time}`,
    ends_at: `${data.date && endsNextDay.value ? nextDay(data.date) : data.date} ${data.end_time}`,
    location: data.location,
    capacity: data.capacity === '' ? null : Number(data.capacity),
    lead_instructor_id: data.lead_instructor_id === '' ? null : data.lead_instructor_id,
    assistant_ids: data.assistant_ids.filter((id) => id !== data.lead_instructor_id),
    ...(isEditing.value ? { status: data.status } : {}),
    notes: data.notes,
    confirm_conflicts: data.confirm_conflicts,
}));

/** Скрытые типы и отключённые инструкторы предлагаются, только если уже стоят в занятии. */
const typeOptions = computed(() =>
    props.eventTypes.filter((eventType) => eventType.isActive || eventType.id === props.event?.eventTypeId),
);

const assignedIds = computed(() => (props.event?.instructors ?? []).map((instructor) => instructor.id));

const instructorOptions = computed(() =>
    props.instructors.filter((instructor) => instructor.isActive || assignedIds.value.includes(instructor.id)),
);

const assistantOptions = computed(() =>
    instructorOptions.value.filter((instructor) => instructor.id !== form.lead_instructor_id),
);

const selectedType = computed(() => props.eventTypes.find((eventType) => eventType.id === form.event_type_id));

const conflicts = ref([]);
const failure = ref('');
const dialog = ref(null);

const timeError = computed(() => form.errors.starts_at || form.errors.ends_at || '');

const assistantsError = computed(
    () => Object.entries(form.errors).find(([field]) => field.startsWith('assistant_ids'))?.[1] ?? '',
);

/** Предупреждение о занятых инструкторах относится к прежнему времени и составу. */
watch(
    () => [form.date, form.start_time, form.end_time, form.lead_instructor_id, form.assistant_ids.join()],
    () => {
        conflicts.value = [];
    },
);

const submit = async (confirmConflicts = false) => {
    failure.value = '';
    form.confirm_conflicts = confirmConflicts;

    try {
        const response = isEditing.value ? await form.patch(`/events/${props.event.id}`) : await form.post('/events');

        if (response) {
            emit('saved', response.data, !isEditing.value);
        }
    } catch (error) {
        if (error?.response?.status === 409) {
            conflicts.value = JSON.parse(error.response.data).conflicts;
            await nextTick();
            document.getElementById('event-conflicts')?.scrollIntoView({ block: 'nearest' });

            return;
        }

        failure.value = 'Не удалось сохранить занятие. Проверьте соединение и попробуйте ещё раз.';
    }
};

/* ---------- Вкладки: данные занятия и его клиенты ---------- */

const tab = ref('details');
const clientsSummary = ref(null);

const clientsTabLabel = computed(() => {
    if (clientsSummary.value === null) {
        return '';
    }

    const { occupied, capacity } = clientsSummary.value;

    return capacity === null ? ` · ${occupied}` : ` · ${occupied} из ${capacity}`;
});

const tabClass = (name) =>
    tab.value === name
        ? 'border-sea-600 text-ink'
        : 'border-transparent text-muted hover:text-ink';

/**
 * «Занятие проведено» сохраняет форму занятия со статусом «Проведено». Если сервер
 * её не принял, причина видна на первой вкладке — туда и возвращаем.
 */
const markDone = async () => {
    form.status = 'done';
    await submit(false);

    tab.value = 'details';
};

const close = () => emit('close');

onMounted(() => {
    dialog.value.showModal();
});
</script>

<template>
    <dialog
        ref="dialog"
        class="m-auto w-full max-w-2xl rounded-lg bg-white p-0 text-ink shadow-xl backdrop:bg-depth-950/50"
        aria-labelledby="event-dialog-title"
        @cancel.prevent="close"
    >
        <div class="flex max-h-[90vh] flex-col">
            <div class="flex items-start justify-between gap-4 border-b border-line px-6 py-4">
                <div>
                    <h2 id="event-dialog-title" class="text-lg font-semibold">
                        {{ isEditing ? event.title : 'Новое занятие' }}
                    </h2>
                    <p v-if="isEditing && event.isCancelled" class="mt-0.5 text-sm text-muted">Занятие отменено</p>
                </div>
                <button type="button" class="-mr-2 rounded-md p-1.5 text-muted hover:bg-surface hover:text-ink" aria-label="Закрыть" @click="close">
                    <AppIcon name="close" />
                </button>
            </div>

            <div v-if="isEditing" role="tablist" aria-label="Разделы окна занятия" class="flex gap-5 border-b border-line px-6">
                <button
                    id="event-tab-details"
                    type="button"
                    role="tab"
                    aria-controls="event-panel-details"
                    :aria-selected="tab === 'details'"
                    class="-mb-px border-b-2 py-2.5 text-sm font-medium"
                    :class="tabClass('details')"
                    @click="tab = 'details'"
                >
                    Занятие
                </button>
                <button
                    id="event-tab-clients"
                    type="button"
                    role="tab"
                    aria-controls="event-panel-clients"
                    :aria-selected="tab === 'clients'"
                    class="-mb-px border-b-2 py-2.5 text-sm font-medium"
                    :class="tabClass('clients')"
                    @click="tab = 'clients'"
                >
                    Клиенты{{ clientsTabLabel }}
                </button>
            </div>

            <form
                id="event-panel-details"
                v-show="tab === 'details'"
                :role="isEditing ? 'tabpanel' : undefined"
                :aria-labelledby="isEditing ? 'event-tab-details' : undefined"
                class="flex min-h-0 flex-1 flex-col"
                novalidate
                @submit.prevent="submit(false)"
            >
                <div class="space-y-5 overflow-y-auto px-6 py-5">
                    <div class="grid gap-5 sm:grid-cols-2">
                        <FormField id="event_type_id" label="Тип занятия" :error="form.errors.event_type_id">
                            <SelectInput id="event_type_id" v-model="form.event_type_id" required :invalid="Boolean(form.errors.event_type_id)">
                                <option v-if="typeOptions.length === 0" value="" disabled>Нет доступных типов</option>
                                <option v-for="eventType in typeOptions" :key="eventType.id" :value="eventType.id">
                                    {{ eventType.name }}{{ eventType.isActive ? '' : ' (скрыт)' }}
                                </option>
                            </SelectInput>
                        </FormField>

                        <FormField id="title" label="Название" hint="Необязательно, по умолчанию — тип занятия." :error="form.errors.title">
                            <TextInput
                                id="title"
                                v-model="form.title"
                                autocomplete="off"
                                :placeholder="selectedType?.name ?? ''"
                                :invalid="Boolean(form.errors.title)"
                            />
                        </FormField>
                    </div>

                    <fieldset>
                        <legend class="text-sm font-medium text-ink">Время</legend>
                        <div class="mt-1.5 grid grid-cols-[1fr_auto_auto] items-center gap-2 sm:grid-cols-[12rem_auto_auto_auto]">
                            <label for="date" class="sr-only">Дата</label>
                            <TextInput id="date" v-model="form.date" type="date" class="col-span-3 sm:col-span-1" :invalid="Boolean(timeError)" required />
                            <label for="start_time" class="sr-only">Начало</label>
                            <TextInput id="start_time" v-model="form.start_time" type="time" step="300" class="w-28" :invalid="Boolean(timeError)" required />
                            <span class="text-muted" aria-hidden="true">—</span>
                            <label for="end_time" class="sr-only">Конец</label>
                            <TextInput id="end_time" v-model="form.end_time" type="time" step="300" class="w-28" :invalid="Boolean(timeError)" required />
                        </div>
                        <p v-if="timeError" class="mt-1.5 text-sm text-flag">{{ timeError }}</p>
                        <p v-else-if="endsNextDay" class="mt-1.5 text-sm text-muted">Закончится на следующий день.</p>
                    </fieldset>

                    <div class="grid gap-5 sm:grid-cols-[1fr_8rem]">
                        <FormField id="location" label="Место" :error="form.errors.location">
                            <TextInput id="location" v-model="form.location" autocomplete="off" :invalid="Boolean(form.errors.location)" />
                        </FormField>

                        <FormField id="capacity" label="Мест" :error="form.errors.capacity">
                            <TextInput
                                id="capacity"
                                v-model="form.capacity"
                                type="number"
                                min="1"
                                max="500"
                                inputmode="numeric"
                                placeholder="без лимита"
                                :invalid="Boolean(form.errors.capacity)"
                            />
                        </FormField>
                    </div>

                    <FormField id="lead_instructor_id" label="Ведущий инструктор" :error="form.errors.lead_instructor_id">
                        <SelectInput
                            id="lead_instructor_id"
                            v-model="form.lead_instructor_id"
                            required
                            :invalid="Boolean(form.errors.lead_instructor_id)"
                        >
                            <option value="" disabled>Выберите инструктора</option>
                            <option v-for="instructor in instructorOptions" :key="instructor.id" :value="instructor.id">
                                {{ instructor.name }}{{ instructor.isActive ? '' : ' (отключён)' }}
                            </option>
                        </SelectInput>
                    </FormField>

                    <fieldset v-if="assistantOptions.length">
                        <legend class="text-sm font-medium text-ink">Помощники</legend>
                        <div class="mt-2 flex flex-wrap gap-x-5 gap-y-2">
                            <label v-for="instructor in assistantOptions" :key="instructor.id" class="flex items-center gap-2 text-sm">
                                <input
                                    v-model="form.assistant_ids"
                                    type="checkbox"
                                    :value="instructor.id"
                                    class="size-4 rounded border-line accent-sea-600"
                                />
                                <span class="size-2.5 rounded-full" :style="{ backgroundColor: instructor.color || '#94a3b8' }" aria-hidden="true" />
                                {{ instructor.name }}
                            </label>
                        </div>
                        <p v-if="assistantsError" class="mt-1.5 text-sm text-flag">{{ assistantsError }}</p>
                    </fieldset>

                    <FormField v-if="isEditing" id="status" label="Статус" :error="form.errors.status">
                        <SelectInput id="status" v-model="form.status" class="sm:max-w-xs" :invalid="Boolean(form.errors.status)">
                            <option v-for="status in statuses" :key="status.value" :value="status.value">{{ status.label }}</option>
                        </SelectInput>
                    </FormField>

                    <FormField id="notes" label="Заметки" :error="form.errors.notes">
                        <TextArea id="notes" v-model="form.notes" :invalid="Boolean(form.errors.notes)" />
                    </FormField>

                    <div
                        v-if="conflicts.length"
                        id="event-conflicts"
                        role="alert"
                        class="rounded-md border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-900"
                    >
                        <p class="font-medium">В это время инструктор уже занят:</p>
                        <ul class="mt-1.5 space-y-1">
                            <li v-for="conflict in conflicts" :key="`${conflict.eventId}-${conflict.instructor}`">
                                <span class="font-medium">{{ conflict.instructor }}</span> — {{ conflict.title }}, {{ conflict.time }}
                            </li>
                        </ul>
                        <button
                            type="button"
                            class="mt-3 rounded-md border border-amber-400 bg-white px-3 py-1.5 font-medium text-amber-900 hover:bg-amber-100 disabled:opacity-60"
                            :disabled="form.processing"
                            @click="submit(true)"
                        >
                            Сохранить всё равно
                        </button>
                    </div>

                    <p v-if="failure" role="alert" class="text-sm text-flag">{{ failure }}</p>
                </div>

                <div class="flex items-center gap-4 border-t border-line px-6 py-4">
                    <PrimaryButton :processing="form.processing">
                        {{ isEditing ? 'Сохранить' : 'Создать занятие' }}
                    </PrimaryButton>
                    <button type="button" class="text-sm text-muted hover:text-ink" @click="close">Отмена</button>
                </div>
            </form>

            <EventClientsPanel
                v-if="isEditing"
                id="event-panel-clients"
                v-show="tab === 'clients'"
                role="tabpanel"
                aria-labelledby="event-tab-clients"
                :event="event"
                :attendance-statuses="attendanceStatuses"
                :request="request"
                @summary="clientsSummary = $event"
                @mark-done="markDone"
            />
        </div>
    </dialog>
</template>

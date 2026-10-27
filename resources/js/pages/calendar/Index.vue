<script setup>
import { http } from '@inertiajs/vue3';
import { computed, ref } from 'vue';
import VueCal from 'vue-cal';
import 'vue-cal/dist/vuecal.css';
import EventDialog from '../../components/EventDialog.vue';
import AppLayout from '../../layouts/AppLayout.vue';

const props = defineProps({
    initialDate: { type: String, required: true },
    initialView: { type: String, required: true },
    instructors: { type: Array, required: true },
    eventTypes: { type: Array, required: true },
    statuses: { type: Array, required: true },
    attendanceStatuses: { type: Array, required: true },
    canCreate: { type: Boolean, required: true },
});

const activeView = ref(props.initialView);
const selectedDate = ref(props.initialDate);
const events = ref([]);
const loading = ref(false);
const notice = ref('');

const pad = (number) => String(number).padStart(2, '0');

/** Дата в виде YYYY-MM-DD по местным часам браузера: vue-cal работает с ними же. */
const formatDate = (date) => `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
const formatDateTime = (date) => `${formatDate(date)} ${pad(date.getHours())}:${pad(date.getMinutes())}`;

/**
 * Запрос к серверу. Ответы 4xx приходят как исключение с полем response,
 * поэтому здесь они превращаются в обычный результат { status, data }.
 */
const request = async (method, url, data = null) => {
    try {
        const response = await http.getClient().request({
            method,
            url,
            data,
            headers: { Accept: 'application/json' },
        });

        return { status: response.status, data: response.data ? JSON.parse(response.data) : null };
    } catch (error) {
        if (error?.response) {
            return { status: error.response.status, data: error.response.data ? JSON.parse(error.response.data) : null };
        }

        return { status: 0, data: null };
    }
};

/* ---------- Загрузка занятий за видимый период ---------- */

const range = ref(null);
let loadId = 0;

const loadEvents = async () => {
    if (!range.value) {
        return;
    }

    const id = ++loadId;
    loading.value = true;

    const { status, data } = await request('get', `/calendar/events?start=${range.value.start}&end=${range.value.end}`);

    if (id !== loadId) {
        return;
    }

    loading.value = false;

    if (status === 200) {
        events.value = data.data;
    } else {
        notice.value = 'Не удалось загрузить занятия. Обновите страницу.';
    }
};

/**
 * Запоминаем вид и дату в адресе, чтобы после обновления страницы календарь
 * открылся там же, где был.
 */
const rememberPosition = (view, date) => {
    const url = new URL(window.location.href);
    url.searchParams.set('view', view);
    url.searchParams.set('date', formatDate(date));
    window.history.replaceState(window.history.state, '', url);
};

const onViewChange = (view) => {
    const start = view.firstCellDate ?? view.startDate;
    const end = view.lastCellDate ?? view.endDate;

    range.value = { start: formatDate(start), end: formatDate(end) };
    activeView.value = view.view;
    rememberPosition(view.view, view.startDate);
    loadEvents();
};

/* ---------- Инструкторы и колонки дневного вида ---------- */

const instructorsById = computed(() => new Map(props.instructors.map((instructor) => [instructor.id, instructor])));

/**
 * В дневном виде у каждого инструктора своя колонка. Отключённые инструкторы
 * получают колонку, только если у них есть занятия в этот день.
 */
const splits = computed(() => {
    if (activeView.value !== 'day') {
        return [];
    }

    const busyIds = new Set(events.value.flatMap((event) => event.instructors.map((instructor) => instructor.id)));

    return props.instructors
        .filter((instructor) => instructor.isActive || busyIds.has(instructor.id))
        .map((instructor) => ({ id: instructor.id, label: instructor.name, color: instructor.color }));
});

/** Белый или тёмный текст — что лучше читается на цвете инструктора. */
const textColorFor = (hex) => {
    const match = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex ?? '');

    if (!match) {
        return '#ffffff';
    }

    const [red, green, blue] = match.slice(1).map((part) => parseInt(part, 16) / 255);
    const luminance = 0.2126 * red + 0.7152 * green + 0.0722 * blue;

    return luminance > 0.6 ? '#12262e' : '#ffffff';
};

const calendarEvents = computed(() =>
    events.value.flatMap((event) => {
        const editable = event.canUpdate && !event.isCancelled;
        const base = {
            start: event.start,
            end: event.end,
            title: event.title,
            class: event.isCancelled ? 'is-cancelled' : '',
            draggable: editable,
            resizable: editable,
            deletable: false,
            titleEditable: false,
            raw: event,
        };

        if (splits.value.length === 0) {
            return [base];
        }

        // Занятие с несколькими инструкторами видно в колонке каждого из них.
        return event.instructors.map((instructor) => ({ ...base, split: instructor.id }));
    }),
);

/* ---------- Окно занятия ---------- */

const dialog = ref(null);
let dialogKey = 0;

const openNew = ({ start, end, leadInstructorId = null }) => {
    if (!props.canCreate) {
        return;
    }

    dialog.value = { key: ++dialogKey, event: null, draft: { start, end, leadInstructorId } };
};

const openExisting = (event) => {
    dialog.value = { key: ++dialogKey, event, draft: {} };
};

const closeDialog = () => {
    dialog.value = null;
};

const onSaved = (event, isNew) => {
    closeDialog();
    notice.value = isNew ? `Занятие создано: ${event.title}.` : `Изменения сохранены: ${event.title}.`;
    loadEvents();
};

/** Новое занятие на ближайший час от выбранного времени, по умолчанию с 10:00. */
const draftAt = (date, split, withTime) => {
    const start = new Date(date);

    if (withTime) {
        start.setMinutes(Math.floor(start.getMinutes() / 30) * 30, 0, 0);
    } else {
        start.setHours(10, 0, 0, 0);
    }

    const end = new Date(start.getTime() + 60 * 60 * 1000);

    return { start: formatDateTime(start), end: formatDateTime(end), leadInstructorId: split ?? null };
};

const createFromButton = () => {
    const date = new Date(`${selectedDate.value}T00:00:00`);
    openNew(draftAt(Number.isNaN(date.getTime()) ? new Date() : date, null, false));
};

let lastEventClickAt = 0;

const onEventClick = (event) => {
    lastEventClickAt = Date.now();
    openExisting(event.raw);
};

const onCellDblclick = (payload) => {
    // Двойной щелчок по самому занятию открывает его, а не новое.
    if (Date.now() - lastEventClickAt < 600) {
        return;
    }

    const date = payload instanceof Date ? payload : payload.date;
    openNew(draftAt(date, payload.split, activeView.value !== 'month'));
};

/**
 * Выделение слота мышью: vue-cal сразу рисует временное занятие. Убираем его
 * и открываем окно с выбранным временем — сохранится только то, что подтвердят.
 */
let removeDraggedEvent = null;

const onEventCreate = (event, deleteEvent) => {
    removeDraggedEvent = deleteEvent;

    return true;
};

const onEventDragCreate = (event) => {
    setTimeout(() => {
        removeDraggedEvent?.();
        removeDraggedEvent = null;
        openNew({ start: formatDateTime(event.start), end: formatDateTime(event.end), leadInstructorId: event.split ?? null });
    });
};

/* ---------- Перенос и растягивание ---------- */

const confirmation = ref(null);

const payloadFor = (event, changes) => ({
    event_type_id: event.eventTypeId,
    title: event.customTitle,
    starts_at: event.start,
    ends_at: event.end,
    location: event.location,
    capacity: event.capacity,
    notes: event.notes,
    status: event.status,
    lead_instructor_id: event.leadInstructorId,
    assistant_ids: event.assistantIds,
    confirm_conflicts: false,
    ...changes,
});

const saveChanges = async (event, changes) => {
    const payload = payloadFor(event, changes);
    const { status, data } = await request('patch', `/events/${event.id}`, payload);

    if (status === 200) {
        notice.value = `Изменения сохранены: ${data.data.title}.`;
        loadEvents();

        return;
    }

    if (status === 409) {
        confirmation.value = { event, payload, conflicts: data.conflicts };

        return;
    }

    notice.value = data?.errors ? Object.values(data.errors)[0][0] : 'Не удалось перенести занятие.';
    loadEvents();
};

const confirmMove = async () => {
    const { event, payload } = confirmation.value;
    confirmation.value = null;
    await saveChanges(event, { ...payload, confirm_conflicts: true });
};

const cancelMove = () => {
    confirmation.value = null;
    loadEvents();
};

/**
 * Перетаскивание в колонку другого инструктора меняет и состав: тот, из чьей колонки
 * занятие унесли, уступает место тому, к кому его положили, с той же ролью.
 */
const instructorsAfterMove = (event, oldSplit, newSplit) => {
    if (newSplit == null || oldSplit === newSplit || event.instructors.some((instructor) => instructor.id === newSplit)) {
        return {};
    }

    if (event.leadInstructorId === oldSplit) {
        return { lead_instructor_id: newSplit };
    }

    return { assistant_ids: event.assistantIds.map((id) => (id === oldSplit ? newSplit : id)) };
};

const onEventDrop = ({ event, oldSplit, newSplit }) => {
    saveChanges(event.raw, {
        starts_at: formatDateTime(event.start),
        ends_at: formatDateTime(event.end),
        ...instructorsAfterMove(event.raw, oldSplit, newSplit),
    });
};

const onDurationChange = ({ event }) => {
    saveChanges(event.raw, {
        starts_at: formatDateTime(event.start),
        ends_at: formatDateTime(event.end),
    });
};

const instructorName = (id) => instructorsById.value.get(id)?.name ?? '';
</script>

<template>
    <AppLayout title="Календарь">
        <template #actions>
            <button
                v-if="canCreate"
                type="button"
                class="inline-flex items-center justify-center rounded-md bg-sea-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-sea-700"
                @click="createFromButton"
            >
                Новое занятие
            </button>
        </template>

        <div class="mb-3 flex min-h-6 flex-wrap items-center justify-between gap-x-6 gap-y-2 text-sm">
            <p class="text-muted">
                Выделите время мышью или дважды щёлкните по ячейке, чтобы создать занятие. Занятие можно перетащить и
                растянуть.
            </p>
            <p v-if="loading" class="text-muted" role="status">Загрузка…</p>
        </div>

        <p
            v-if="notice"
            role="status"
            class="mb-3 flex items-start justify-between gap-4 rounded-md border border-sea-100 bg-sea-50 px-3 py-2 text-sm text-sea-700"
        >
            <span>{{ notice }}</span>
            <button type="button" class="shrink-0 underline-offset-4 hover:underline" @click="notice = ''">Скрыть</button>
        </p>

        <div
            v-if="activeView === 'day' && splits.length === 0"
            class="mb-3 rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900"
        >
            Нет активных инструкторов — колонки по инструкторам появятся, когда они будут добавлены.
        </div>

        <div class="calendar h-[calc(100vh-14rem)] min-h-[34rem] overflow-hidden rounded-lg border border-line bg-white">
            <VueCal
                v-model:active-view="activeView"
                v-model:selected-date="selectedDate"
                locale="ru"
                :disable-views="['years', 'year']"
                :events="calendarEvents"
                :split-days="splits"
                :sticky-split-labels="true"
                :min-split-width="activeView === 'day' ? 150 : 0"
                :time-from="7 * 60"
                :time-to="23 * 60"
                :time-step="30"
                :time-cell-height="34"
                :snap-to-time="15"
                :editable-events="{ title: false, drag: true, resize: true, delete: false, create: canCreate }"
                :cell-click-hold="false"
                :drag-to-create-event="canCreate"
                :dblclick-to-navigate="false"
                :click-to-navigate="activeView === 'month'"
                events-on-month-view
                :watch-real-time="true"
                today-button
                :on-event-click="onEventClick"
                :on-event-create="onEventCreate"
                @ready="onViewChange"
                @view-change="onViewChange"
                @cell-dblclick="onCellDblclick"
                @event-drag-create="onEventDragCreate"
                @event-drop="onEventDrop"
                @event-duration-change="onDurationChange"
            >
                <template #split-label="{ split }">
                    <span class="flex items-center justify-center gap-1.5 truncate px-1 text-xs font-medium text-ink">
                        <span class="size-2.5 shrink-0 rounded-full" :style="{ backgroundColor: split.color || '#94a3b8' }" aria-hidden="true" />
                        <span class="truncate">{{ split.label }}</span>
                    </span>
                </template>

                <template #no-event>
                    <span class="sr-only">Нет занятий</span>
                </template>

                <template #event="{ event, view }">
                    <!-- Временное занятие, которое vue-cal рисует, пока выделяют слот мышью. -->
                    <div v-if="!event.raw" class="event-card is-draft" />
                    <div
                        v-else
                        class="event-card"
                        :style="{
                            backgroundColor: event.raw.color || '#64748b',
                            color: textColorFor(event.raw.color || '#64748b'),
                        }"
                    >
                        <template v-if="view === 'month'">
                            <span class="font-medium">{{ event.raw.start.slice(11) }}</span>
                            {{ event.title }}
                        </template>
                        <template v-else>
                            <p class="truncate font-medium">{{ event.title }}</p>
                            <p class="truncate opacity-90">{{ event.raw.start.slice(11) }}–{{ event.raw.end.slice(11) }}</p>
                            <p v-if="event.raw.location" class="truncate opacity-90">{{ event.raw.location }}</p>
                            <p v-if="view !== 'day' || event.raw.instructors.length > 1" class="truncate opacity-90">
                                {{ event.raw.instructors.map((instructor) => instructor.name).join(', ') }}
                            </p>
                        </template>
                    </div>
                </template>
            </VueCal>
        </div>

        <EventDialog
            v-if="dialog"
            :key="dialog.key"
            :event="dialog.event"
            :draft="dialog.draft"
            :instructors="instructors"
            :event-types="eventTypes"
            :statuses="statuses"
            :attendance-statuses="attendanceStatuses"
            :request="request"
            @saved="onSaved"
            @close="closeDialog"
        />

        <dialog
            v-if="confirmation"
            open
            class="fixed inset-0 z-50 m-auto h-fit w-full max-w-md rounded-lg border border-line bg-white p-6 text-ink shadow-xl"
            aria-labelledby="move-conflict-title"
        >
            <h2 id="move-conflict-title" class="text-lg font-semibold">Инструктор уже занят</h2>
            <p class="mt-2 text-sm text-muted">В новое время у инструктора есть другое занятие:</p>
            <ul class="mt-2 space-y-1 text-sm">
                <li v-for="conflict in confirmation.conflicts" :key="`${conflict.eventId}-${conflict.instructor}`">
                    <span class="font-medium">{{ conflict.instructor }}</span> — {{ conflict.title }}, {{ conflict.time }}
                </li>
            </ul>
            <p v-if="confirmation.payload.lead_instructor_id !== confirmation.event.leadInstructorId" class="mt-3 text-sm">
                Ведущим станет {{ instructorName(confirmation.payload.lead_instructor_id) }}.
            </p>
            <div class="mt-5 flex items-center gap-4">
                <button
                    type="button"
                    class="rounded-md bg-sea-600 px-4 py-2 text-sm font-medium text-white hover:bg-sea-700"
                    @click="confirmMove"
                >
                    Перенести всё равно
                </button>
                <button type="button" class="text-sm text-muted hover:text-ink" @click="cancelMove">Не переносить</button>
            </div>
        </dialog>
        <div v-if="confirmation" class="fixed inset-0 z-40 bg-depth-950/50" aria-hidden="true" />
    </AppLayout>
</template>

<style>
.calendar .vuecal {
    --vuecal-accent: var(--color-sea-600);
}

.calendar .vuecal__menu,
.calendar .vuecal__cell-events-count {
    background-color: var(--color-sea-600);
}

.calendar .vuecal__title-bar {
    background-color: var(--color-sea-50);
}

.calendar .vuecal__menu {
    background-color: var(--color-depth-900);
}

.calendar .vuecal__view-btn {
    color: var(--color-depth-300);
}

.calendar .vuecal__view-btn--active {
    color: #fff;
    border-bottom-color: #fff;
    background-color: transparent;
}

.calendar .vuecal__cell--today,
.calendar .vuecal__cell--current {
    background-color: rgb(232 244 246 / 0.6);
}

.calendar .vuecal__cell--selected {
    background-color: rgb(207 232 237 / 0.4);
}

.calendar .vuecal__event {
    background: transparent;
    color: inherit;
    border: none;
    padding: 1px;
    text-align: left;
    cursor: pointer;
}

.calendar .vuecal__event .event-card {
    height: 100%;
    overflow: hidden;
    border-radius: 4px;
    padding: 2px 6px;
    font-size: 12px;
    line-height: 1.35;
    box-shadow: inset 0 0 0 1px rgb(0 0 0 / 0.08);
}

.calendar .vuecal--month-view .vuecal__cell-content {
    justify-content: flex-start;
    padding-top: 4px;
}

.calendar .vuecal--month-view .vuecal__event .event-card {
    height: auto;
    white-space: nowrap;
    text-overflow: ellipsis;
}

.calendar .vuecal__event .event-card.is-draft {
    background-color: rgb(15 124 143 / 0.25);
    box-shadow: inset 0 0 0 1px var(--color-sea-600);
}

.calendar .vuecal__event.is-cancelled .event-card {
    opacity: 0.45;
    text-decoration: line-through;
}

.calendar .vuecal__event--focus .event-card {
    box-shadow: 0 0 0 2px var(--color-ink);
}

.calendar .vuecal__event-resize-handle {
    background-color: rgb(0 0 0 / 0.12);
}

.calendar .vuecal__split-days-headers .day-split-header,
.calendar .vuecal__cell-split .split-label {
    font-size: 12px;
}
</style>

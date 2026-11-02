<script setup>
import { Link, http, usePage } from '@inertiajs/vue3';
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue';
import VueCal from 'vue-cal';
import 'vue-cal/dist/vuecal.css';
import EventDialog from '../../components/EventDialog.vue';
import FormField from '../../components/FormField.vue';
import SelectInput from '../../components/SelectInput.vue';
import AppLayout from '../../layouts/AppLayout.vue';

const props = defineProps({
    initialDate: { type: String, required: true },
    initialView: { type: String, required: true },
    /** Фильтры из адреса страницы: { instructorId, eventTypeId }, null — без фильтра. */
    initialFilters: { type: Object, required: true },
    instructors: { type: Array, required: true },
    eventTypes: { type: Array, required: true },
    statuses: { type: Array, required: true },
    attendanceStatuses: { type: Array, required: true },
    canCreate: { type: Boolean, required: true },
});

const page = usePage();

const activeView = ref(props.initialView);
const selectedDate = ref(props.initialDate);
const events = ref([]);
const loading = ref(false);
const loaded = ref(false);
const notice = ref('');

/** Пустая строка — «все»: так её отдаёт и принимает выпадающий список. */
const instructorFilter = ref(props.initialFilters.instructorId ?? '');
const typeFilter = ref(props.initialFilters.eventTypeId ?? '');

const filterType = computed(() => props.eventTypes.find((eventType) => eventType.id === typeFilter.value));

/** Тип в фильтре выбирается в два шага: родитель и, если они есть, его вложенный тип. */
const parentTypeFilter = computed({
    get: () => (filterType.value?.parentId ?? filterType.value?.id ?? ''),
    set: (id) => {
        typeFilter.value = id;
    },
});

const childTypeFilter = computed({
    get: () => (filterType.value?.parentId ? filterType.value.id : ''),
    set: (id) => {
        typeFilter.value = id || parentTypeFilter.value;
    },
});

const parentTypes = computed(() => props.eventTypes.filter((eventType) => !eventType.parentId));

const childTypes = computed(() =>
    props.eventTypes.filter((eventType) => eventType.parentId !== null && eventType.parentId === parentTypeFilter.value),
);

const hasFilters = computed(() => instructorFilter.value !== '' || typeFilter.value !== '');

const isInstructor = computed(() => page.props.auth.user.roles.includes('instructor'));

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

    const query = new URLSearchParams({ start: range.value.start, end: range.value.end });

    if (instructorFilter.value !== '') {
        query.set('instructor_id', instructorFilter.value);
    }
    if (typeFilter.value !== '') {
        query.set('event_type_id', typeFilter.value);
    }

    const { status, data } = await request('get', `/calendar/events?${query}`);

    if (id !== loadId) {
        return;
    }

    loading.value = false;

    if (status === 200) {
        events.value = data.data;
        loaded.value = true;
    } else {
        notice.value = 'Не удалось загрузить занятия. Обновите страницу.';
    }
};

/**
 * Запоминаем вид, дату и фильтры в адресе, чтобы после обновления страницы календарь
 * открылся там же, где был, а ссылкой можно было поделиться.
 */
let position = null;

const rememberPosition = () => {
    if (position === null) {
        return;
    }

    const url = new URL(window.location.href);
    url.searchParams.set('view', position.view);
    url.searchParams.set('date', formatDate(position.date));

    for (const [name, value] of [
        ['instructor_id', instructorFilter.value],
        ['event_type_id', typeFilter.value],
    ]) {
        if (value === '') {
            url.searchParams.delete(name);
        } else {
            url.searchParams.set(name, value);
        }
    }

    window.history.replaceState(window.history.state, '', url);
};

const onViewChange = (view) => {
    const start = view.firstCellDate ?? view.startDate;
    const end = view.lastCellDate ?? view.endDate;

    range.value = { start: formatDate(start), end: formatDate(end) };
    activeView.value = view.view;
    position = { view: view.view, date: view.startDate };
    rememberPosition();
    loadEvents();
};

watch([instructorFilter, typeFilter], () => {
    rememberPosition();
    loadEvents();
});

const resetFilters = () => {
    instructorFilter.value = '';
    typeFilter.value = '';
};

/* ---------- Инструкторы и колонки дневного вида ---------- */

/** Колонка занятий без инструктора в дневном виде. */
const UNASSIGNED = 'unassigned';

/** Инструктор, которому принадлежит колонка; у колонки «Без инструктора» его нет. */
const instructorOfSplit = (split) => (split === UNASSIGNED ? null : (split ?? null));

const instructorsById = computed(() => new Map(props.instructors.map((instructor) => [instructor.id, instructor])));

/**
 * В дневном виде у каждого инструктора своя колонка; с фильтром по инструктору
 * остаётся одна. В конце стоит колонка занятий без инструктора. Отключённые инструкторы получают колонку, только если у них есть
 * занятия в этот день.
 */
const splits = computed(() => {
    if (activeView.value !== 'day') {
        return [];
    }

    const busyIds = new Set(events.value.flatMap((event) => event.instructors.map((instructor) => instructor.id)));

    const columns = props.instructors
        .filter((instructor) => instructorFilter.value === '' || instructor.id === instructorFilter.value)
        .filter((instructor) => instructor.isActive || busyIds.has(instructor.id))
        .map((instructor) => ({ id: instructor.id, label: instructor.name, color: instructor.color }));

    if (instructorFilter.value === '') {
        columns.push({ id: UNASSIGNED, label: 'Без инструктора', color: null });
    }

    return columns;
});

const splitIds = computed(() => new Set(splits.value.map((split) => split.id)));

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
            class: [event.isCancelled && 'is-cancelled', event.isMine && 'is-mine'].filter(Boolean).join(' '),
            draggable: editable,
            resizable: editable,
            deletable: false,
            titleEditable: false,
            raw: event,
        };

        if (splits.value.length === 0) {
            return [base];
        }

        if (event.instructors.length === 0) {
            return splitIds.value.has(UNASSIGNED) ? [{ ...base, split: UNASSIGNED }] : [];
        }

        // Занятие с несколькими инструкторами видно в колонке каждого из них.
        return event.instructors
            .filter((instructor) => splitIds.value.has(instructor.id))
            .map((instructor) => ({ ...base, split: instructor.id }));
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

const copyExisting = (event) => {
    dialog.value = { key: ++dialogKey, event: null, template: event, draft: {} };
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

    return { start: formatDateTime(start), end: formatDateTime(end), leadInstructorId: instructorOfSplit(split) };
};

const createFromButton = () => {
    const date = new Date(`${selectedDate.value}T00:00:00`);
    openNew(draftAt(Number.isNaN(date.getTime()) ? new Date() : date, null, false));
};

/** Открывает выбранный день в дневном виде. */
const shortWeekdays = {
    понедельник: 'пн',
    вторник: 'вт',
    среда: 'ср',
    четверг: 'чт',
    пятница: 'пт',
    суббота: 'сб',
    воскресенье: 'вс',
};

const shortWeekday = (heading) => shortWeekdays[heading.label.toLowerCase()] ?? heading.label.slice(0, 2).toLowerCase();

const openDay = (date) => {
    selectedDate.value = formatDate(date);
    activeView.value = 'day';
};

const onCellClick = (payload) => {
    if (activeView.value === 'month') {
        openDay(payload instanceof Date ? payload : payload.date);
    }
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
        openNew({ start: formatDateTime(event.start), end: formatDateTime(event.end), leadInstructorId: instructorOfSplit(event.split) });
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

    if (newSplit === UNASSIGNED) {
        // Без ведущего помощников не бывает: ведущий уходит — занятие остаётся совсем без инструкторов.
        return event.leadInstructorId === oldSplit
            ? { lead_instructor_id: null, assistant_ids: [] }
            : { assistant_ids: event.assistantIds.filter((id) => id !== oldSplit) };
    }

    if (oldSplit === UNASSIGNED) {
        return { lead_instructor_id: newSplit };
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

/* ---------- Пустые состояния ---------- */

/**
 * Занятие нельзя создать без активного инструктора и без доступного типа. Пока их нет,
 * над календарём написано, что добавить, и у администратора есть ссылка туда.
 */
const setupHints = computed(() =>
    [
        !props.instructors.some((instructor) => instructor.isActive) && {
            text: 'Нет активных инструкторов: добавьте хотя бы одного, чтобы создавать занятия. В дневном виде у каждого инструктора будет своя колонка.',
            href: page.props.can.manageInstructors ? '/instructors/create' : null,
            linkLabel: 'Добавить инструктора',
        },
        !props.eventTypes.some((eventType) => eventType.isActive) && {
            text: 'Нет доступных типов занятий: включите или добавьте хотя бы один, чтобы создавать занятия.',
            href: page.props.can.manageEventTypes ? '/settings/event-types' : null,
            linkLabel: 'Открыть типы занятий',
        },
    ].filter(Boolean),
);

const mobileQuery = typeof window === 'undefined' ? null : window.matchMedia('(max-width: 639px)');
const isMobile = ref(mobileQuery?.matches ?? false);
const updateIsMobile = (event) => {
    isMobile.value = event.matches;
};

onMounted(() => mobileQuery?.addEventListener('change', updateIsMobile));
onBeforeUnmount(() => mobileQuery?.removeEventListener('change', updateIsMobile));

/** Период загружен, и в нём ничего нет: с фильтрами это «ничего не нашли», без них — свободный период. */
const isEmptyPeriod = computed(() => loaded.value && !loading.value && events.value.length === 0);
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

        <form class="mb-2 flex flex-wrap sm:mb-4 items-end gap-x-4 gap-y-3" aria-label="Фильтры календаря" @submit.prevent>
            <FormField id="filter-instructor" label="Инструктор" class="w-full sm:w-56">
                <SelectInput id="filter-instructor" v-model="instructorFilter">
                    <option value="">Все инструкторы</option>
                    <option v-for="instructor in instructors" :key="instructor.id" :value="instructor.id">
                        {{ instructor.name }}{{ instructor.isActive ? '' : ' (отключён)' }}
                    </option>
                </SelectInput>
            </FormField>

            <FormField id="filter-type" label="Тип занятия" class="w-full sm:w-56">
                <SelectInput id="filter-type" v-model="parentTypeFilter">
                    <option value="">Все типы</option>
                    <option v-for="eventType in parentTypes" :key="eventType.id" :value="eventType.id">
                        {{ eventType.shortName }}{{ eventType.isActive ? '' : ' (скрыт)' }}
                    </option>
                </SelectInput>
            </FormField>

            <FormField v-if="childTypes.length > 0" id="filter-child-type" label="Вложенный тип" class="w-full sm:w-56">
                <SelectInput id="filter-child-type" v-model="childTypeFilter">
                    <option value="">—</option>
                    <option v-for="eventType in childTypes" :key="eventType.id" :value="eventType.id">
                        {{ eventType.shortName }}{{ eventType.isActive ? '' : ' (скрыт)' }}
                    </option>
                </SelectInput>
            </FormField>

            <button
                v-if="hasFilters"
                type="button"
                class="pb-2 text-sm text-sea-700 underline-offset-4 hover:underline"
                @click="resetFilters"
            >
                Сбросить фильтры
            </button>
        </form>

        <div class="flex flex-wrap sm:mb-3 sm:min-h-6 items-center justify-between gap-x-6 gap-y-2 text-sm">
            <p class="hidden text-muted sm:block">
                Выделите время мышью или дважды щёлкните по ячейке, чтобы создать занятие. Занятие можно перетащить и
                растянуть.
                <template v-if="isInstructor">Ваши занятия обведены рамкой.</template>
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
            v-for="hint in setupHints"
            :key="hint.text"
            class="mb-3 rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900"
        >
            {{ hint.text }}
            <Link v-if="hint.href" :href="hint.href" class="ml-1 font-medium underline underline-offset-4">{{ hint.linkLabel }}</Link>
        </div>

        <div
            v-if="isEmptyPeriod"
            role="status"
            class="mb-3 hidden rounded-md border border-dashed border-line bg-white px-4 py-3 text-sm text-muted sm:block"
        >
            <template v-if="hasFilters">
                По выбранным фильтрам в этот период занятий нет.
                <button type="button" class="ml-1 text-sea-700 underline-offset-4 hover:underline" @click="resetFilters">
                    Сбросить фильтры
                </button>
            </template>
            <template v-else>
                В этот период занятий нет.
                <template v-if="canCreate">Создайте занятие кнопкой «Новое занятие» или выделите время в календаре.</template>
            </template>
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
                :drag-to-create-event="canCreate && !isMobile"
                :dblclick-to-navigate="false"
                :click-to-navigate="false"
                events-on-month-view
                :watch-real-time="true"
                today-button
                :on-event-click="onEventClick"
                :on-event-create="onEventCreate"
                @ready="onViewChange"
                @view-change="onViewChange"
                @cell-click="onCellClick"
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

                <template #title="{ title, view }">
                    <template v-if="view.id === 'week'">
                        <span class="hidden sm:inline">{{ title }}</span>
                        <span class="sm:hidden">{{ title.replace(/^[^(]*\(([^)]*)\)$/, '$1') }}</span>
                    </template>
                    <template v-else>{{ title }}</template>
                </template>

                <template #weekday-heading="{ heading, view }">
                    <button
                        v-if="view.id === 'week'"
                        type="button"
                        class="cursor-pointer underline-offset-4 hover:underline"
                        @click.stop="openDay(heading.date)"
                    >
                        <span class="hidden sm:inline">{{ heading.label }}</span>
                        <span class="sm:hidden">{{ shortWeekday(heading) }}</span>
                        {{ heading.date.getDate() }}
                    </button>
                    <template v-else>
                        <span class="hidden sm:inline">{{ heading.label }}</span>
                        <span class="sm:hidden">{{ shortWeekday(heading) }}</span>
                    </template>
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
                        <span v-if="event.raw.isMine" class="sr-only">Ваше занятие. </span>
                        <template v-if="view === 'month'">
                            <span class="font-medium">{{ event.raw.start.slice(11) }}</span>
                            {{ event.title }}
                        </template>
                        <template v-else>
                            <p class="truncate font-medium">{{ event.title }}</p>
                            <p class="truncate opacity-90">{{ event.raw.start.slice(11) }}–{{ event.raw.end.slice(11) }}</p>
                            <p v-if="event.raw.location" class="truncate opacity-90">{{ event.raw.location }}</p>
                            <p class="truncate opacity-90">
                                ({{ event.raw.occupiedPlaces }}<template v-if="event.raw.capacity !== null"> из {{ event.raw.capacity }}</template> чел.)
                            </p>
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
            :template="dialog.template ?? null"
            :can-copy="canCreate"
            :instructors="instructors"
            :event-types="eventTypes"
            :statuses="statuses"
            :attendance-statuses="attendanceStatuses"
            :request="request"
            @saved="onSaved"
            @copy="copyExisting"
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
            <p
                v-if="confirmation.payload.lead_instructor_id && confirmation.payload.lead_instructor_id !== confirmation.event.leadInstructorId"
                class="mt-3 text-sm"
            >
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

/* Своё занятие: двойная внутренняя рамка читается на любом цвете инструктора. */
.calendar .vuecal__event.is-mine .event-card {
    font-weight: 600;
    box-shadow:
        inset 0 0 0 2px var(--color-ink),
        inset 0 0 0 3px rgb(255 255 255 / 0.85);
}

.calendar .vuecal__event--focus .event-card {
    box-shadow: 0 0 0 2px var(--color-ink);
}

.calendar .vuecal__event--focus.is-mine .event-card {
    box-shadow:
        0 0 0 2px var(--color-ink),
        inset 0 0 0 2px var(--color-ink),
        inset 0 0 0 3px rgb(255 255 255 / 0.85);
}

.calendar .vuecal__event-resize-handle {
    background-color: rgb(0 0 0 / 0.12);
}

.calendar .vuecal__split-days-headers .day-split-header,
.calendar .vuecal__cell-split .split-label {
    font-size: 12px;
}
</style>

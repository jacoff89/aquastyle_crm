<script setup>
import { router } from '@inertiajs/vue3';
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue';
import VueCal from 'vue-cal';
import 'vue-cal/dist/vuecal.css';
import '../../../css/calendar.css';
import { formatDate, rememberInAddress, request, shortWeekday, textColorFor } from '../../calendar.js';
import FormField from '../../components/FormField.vue';
import SelectInput from '../../components/SelectInput.vue';
import AppLayout from '../../layouts/AppLayout.vue';

const props = defineProps({
    initialDate: { type: String, required: true },
    initialView: { type: String, required: true },
    /** Фильтры из адреса страницы: { creatorId, channel, status }, null — без фильтра. */
    initialFilters: { type: Object, required: true },
    /** Все пользователи, которые могли записать коммуникацию: { id, name, isActive }. */
    creators: { type: Array, required: true },
    /** Способы связи: { value, label }. */
    channels: { type: Array, required: true },
    /** Статусы коммуникации: { value, label }. */
    statuses: { type: Array, required: true },
});

/** Цвет коммуникации, у создателя которой цвета нет. */
const DEFAULT_COLOR = '#64748b';

const activeView = ref(props.initialView);
const selectedDate = ref(props.initialDate);
const communications = ref([]);
const loading = ref(false);
const loaded = ref(false);
const notice = ref('');

/** Пустая строка — «все»: так её отдаёт и принимает выпадающий список. */
const creatorFilter = ref(props.initialFilters.creatorId ?? '');
const channelFilter = ref(props.initialFilters.channel ?? '');
const statusFilter = ref(props.initialFilters.status ?? '');

const hasFilters = computed(() => creatorFilter.value !== '' || channelFilter.value !== '' || statusFilter.value !== '');

/* ---------- Загрузка коммуникаций за видимый период ---------- */

const range = ref(null);
let loadId = 0;

const loadCommunications = async () => {
    if (!range.value) {
        return;
    }

    const id = ++loadId;
    loading.value = true;

    const query = new URLSearchParams({ start: range.value.start, end: range.value.end });

    if (creatorFilter.value !== '') {
        query.set('creator_id', creatorFilter.value);
    }
    if (channelFilter.value !== '') {
        query.set('channel', channelFilter.value);
    }
    if (statusFilter.value !== '') {
        query.set('status', statusFilter.value);
    }

    const { status, data } = await request('get', `/communications/events?${query}`);

    if (id !== loadId) {
        return;
    }

    loading.value = false;

    if (status === 200) {
        communications.value = data.data;
        loaded.value = true;
    } else {
        notice.value = 'Не удалось загрузить коммуникации. Обновите страницу.';
    }
};

/** Вид, дата и фильтры хранятся в адресе, как в календаре занятий. */
let position = null;

const rememberPosition = () => {
    if (position === null) {
        return;
    }

    rememberInAddress(position.view, position.date, {
        creator_id: creatorFilter.value,
        channel: channelFilter.value,
        status: statusFilter.value,
    });
};

const onViewChange = (view) => {
    const start = view.firstCellDate ?? view.startDate;
    const end = view.lastCellDate ?? view.endDate;

    range.value = { start: formatDate(start), end: formatDate(end) };
    activeView.value = view.view;
    position = { view: view.view, date: view.startDate };
    rememberPosition();
    loadCommunications();
};

watch([creatorFilter, channelFilter, statusFilter], () => {
    rememberPosition();
    loadCommunications();
});

const resetFilters = () => {
    creatorFilter.value = '';
    channelFilter.value = '';
    statusFilter.value = '';
};

/* ---------- Отметки: выполненные и просроченные ---------- */

/**
 * Текущее время, раз в минуту: запланированная коммуникация краснеет, как только
 * её время прошло, без перезагрузки страницы.
 */
const now = ref(new Date());
let clock = null;

onMounted(() => {
    clock = setInterval(() => {
        now.value = new Date();
    }, 60_000);
});

onBeforeUnmount(() => clearInterval(clock));

/** Время с сервера «YYYY-MM-DD HH:MM» по местным часам браузера. */
const parseDateTime = (value) => new Date(value.replace(' ', 'T'));

const isOverdue = (communication) => communication.isPlanned && parseDateTime(communication.start) <= now.value;

const calendarEvents = computed(() =>
    communications.value.map((communication) => ({
        start: communication.start,
        end: communication.end,
        title: communication.clientName,
        class: [!communication.isPlanned && 'is-done', isOverdue(communication) && 'is-overdue'].filter(Boolean).join(' '),
        draggable: false,
        resizable: false,
        deletable: false,
        titleEditable: false,
        raw: communication,
    })),
);

const cardStyle = (communication) => {
    const color = communication.color || DEFAULT_COLOR;

    return { backgroundColor: color, color: textColorFor(color) };
};

/* ---------- Переходы ---------- */

/** Щелчок по коммуникации открывает карточку клиента на списке коммуникаций; с Ctrl или ⌘ — в новой вкладке. */
const onEventClick = (event, domEvent) => {
    const url = `/clients/${event.raw.clientId}#communications-heading`;

    if (domEvent?.ctrlKey || domEvent?.metaKey) {
        window.open(url, '_blank');

        return;
    }

    router.visit(url);
};

/** Открывает выбранный день в дневном виде. */
const openDay = (date) => {
    selectedDate.value = formatDate(date);
    activeView.value = 'day';
};

const onCellClick = (payload) => {
    if (activeView.value === 'month') {
        openDay(payload instanceof Date ? payload : payload.date);
    }
};

/** Период загружен, и в нём ничего нет: с фильтрами это «ничего не нашли», без них — свободный период. */
const isEmptyPeriod = computed(() => loaded.value && !loading.value && communications.value.length === 0);
</script>

<template>
    <AppLayout title="Коммуникации">
        <form class="mb-2 flex flex-wrap items-end gap-x-4 gap-y-3 sm:mb-4" aria-label="Фильтры коммуникаций" @submit.prevent>
            <FormField id="filter-creator" label="Создатель" class="w-full sm:w-56">
                <SelectInput id="filter-creator" v-model="creatorFilter">
                    <option value="">Все</option>
                    <option v-for="creator in creators" :key="creator.id" :value="creator.id">
                        {{ creator.name }}{{ creator.isActive ? '' : ' (отключён)' }}
                    </option>
                </SelectInput>
            </FormField>

            <FormField id="filter-channel" label="Способ связи" class="w-full sm:w-56">
                <SelectInput id="filter-channel" v-model="channelFilter">
                    <option value="">Все способы</option>
                    <option v-for="channel in channels" :key="channel.value" :value="channel.value">
                        {{ channel.label }}
                    </option>
                </SelectInput>
            </FormField>

            <FormField id="filter-status" label="Статус" class="w-full sm:w-56">
                <SelectInput id="filter-status" v-model="statusFilter">
                    <option value="">Все статусы</option>
                    <option v-for="status in statuses" :key="status.value" :value="status.value">
                        {{ status.label }}
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

        <div class="flex flex-wrap items-center justify-between gap-x-6 gap-y-2 text-sm sm:mb-3 sm:min-h-6">
            <p class="hidden items-center gap-x-4 gap-y-1 text-muted sm:flex sm:flex-wrap">
                <span>Щёлкните по коммуникации, чтобы открыть клиента.</span>
                <span class="flex items-center gap-1.5">
                    <span class="size-3 rounded-sm bg-slate-500 opacity-45" aria-hidden="true" />
                    выполнена
                </span>
                <span class="flex items-center gap-1.5">
                    <span class="size-3 rounded-sm bg-flag" aria-hidden="true" />
                    планировалась, время прошло
                </span>
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
            v-if="isEmptyPeriod"
            role="status"
            class="mb-3 hidden rounded-md border border-dashed border-line bg-white px-4 py-3 text-sm text-muted sm:block"
        >
            <template v-if="hasFilters">
                По выбранным фильтрам в этот период коммуникаций нет.
                <button type="button" class="ml-1 text-sea-700 underline-offset-4 hover:underline" @click="resetFilters">
                    Сбросить фильтры
                </button>
            </template>
            <template v-else>
                В этот период коммуникаций нет. Их добавляют на карточке клиента.
            </template>
        </div>

        <div class="calendar h-[calc(100vh-14rem)] min-h-[34rem] overflow-hidden rounded-lg border border-line bg-white">
            <VueCal
                v-model:active-view="activeView"
                v-model:selected-date="selectedDate"
                locale="ru"
                :disable-views="['years', 'year']"
                :events="calendarEvents"
                :time-from="7 * 60"
                :time-to="23 * 60"
                :time-step="30"
                :time-cell-height="34"
                :editable-events="false"
                :cell-click-hold="false"
                :drag-to-create-event="false"
                :dblclick-to-navigate="false"
                :click-to-navigate="false"
                events-on-month-view
                :watch-real-time="true"
                today-button
                :on-event-click="onEventClick"
                @ready="onViewChange"
                @view-change="onViewChange"
                @cell-click="onCellClick"
            >
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
                    <span class="sr-only">Нет коммуникаций</span>
                </template>

                <template #event="{ event, view }">
                    <div class="event-card" :style="cardStyle(event.raw)" :title="event.raw.notes">
                        <span class="sr-only">
                            {{ event.raw.statusLabel }}{{ isOverdue(event.raw) ? ', время прошло' : '' }}.
                        </span>
                        <template v-if="view === 'month'">
                            <span class="font-medium">{{ event.raw.start.slice(11) }}</span>
                            {{ event.title }}
                        </template>
                        <template v-else>
                            <p class="truncate font-medium">{{ event.title }}</p>
                            <p class="truncate opacity-90">{{ event.raw.start.slice(11) }} · {{ event.raw.channelLabel }}</p>
                            <p v-if="event.raw.creatorName" class="truncate opacity-90">{{ event.raw.creatorName }}</p>
                            <p class="truncate opacity-90">{{ event.raw.notes }}</p>
                        </template>
                    </div>
                </template>
            </VueCal>
        </div>
    </AppLayout>
</template>

<style>
/* Запланированная коммуникация, время которой прошло: красная поверх цвета создателя. */
.calendar .vuecal__event.is-overdue .event-card {
    background-color: var(--color-flag) !important;
    color: #fff !important;
}
</style>

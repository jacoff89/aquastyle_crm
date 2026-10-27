<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue';
import FormField from './FormField.vue';
import SelectInput from './SelectInput.vue';
import TextInput from './TextInput.vue';

const props = defineProps({
    /** Сохранённое занятие, чьих клиентов показываем. */
    event: { type: Object, required: true },
    attendanceStatuses: { type: Array, required: true },
    /** Запрос к серверу страницы календаря: отвечает { status, data }, ответы 4xx — обычный результат. */
    request: { type: Function, required: true },
});

const emit = defineEmits(['summary', 'mark-done']);

const bookings = ref([]);
const meta = ref({ capacity: props.event.capacity, occupied: 0, canManage: false, canMarkAttendance: false });
const loading = ref(true);
const message = ref('');
const savingId = ref(null);

/** Любой ответ сервера со списком клиентов заменяет прежний: показываем то, что сохранено. */
const applyListing = (payload) => {
    bookings.value = payload.data;
    meta.value = payload.meta;
    emit('summary', { occupied: payload.meta.occupied, capacity: payload.meta.capacity });
};

const failureText = ({ status, data }, fallback) => {
    if (status === 403) {
        return 'У вас нет прав на это действие.';
    }

    if (status === 422 && data?.errors) {
        return Object.values(data.errors)[0][0];
    }

    return fallback;
};

const load = async () => {
    const result = await props.request('get', `/events/${props.event.id}/clients`);

    loading.value = false;

    if (result.status === 200) {
        applyListing(result.data);
    } else {
        message.value = 'Не удалось загрузить список клиентов. Закройте окно и откройте его снова.';
    }
};

onMounted(load);

const isFull = computed(() => meta.value.capacity !== null && meta.value.occupied >= meta.value.capacity);
const canAdd = computed(() => meta.value.canManage && !props.event.isCancelled);
const unmarkedCount = computed(() => bookings.value.filter((row) => row.status === 'booked').length);
const listedIds = computed(() => new Set(bookings.value.map((row) => row.clientId)));

const capacityLabel = computed(() =>
    meta.value.capacity === null
        ? `Записано: ${meta.value.occupied}`
        : `Записано: ${meta.value.occupied} из ${meta.value.capacity}`,
);

const bookingUrl = (row) => `/events/${props.event.id}/clients/${row.clientId}`;

/* ---------- Статус и заметка клиента ---------- */

/** «Пришёл» и «Не пришёл» отмечают только администратор и инструкторы этого занятия. */
const isLocked = (row) => !meta.value.canManage || (row.isAttendanceMark && !meta.value.canMarkAttendance);

const isOptionDisabled = (status, row) => {
    if (status.value === row.status) {
        return false;
    }

    if (status.isAttendanceMark && !meta.value.canMarkAttendance) {
        return true;
    }

    return props.event.isCancelled && status.value !== 'cancelled';
};

const changeStatus = async (row, status) => {
    if (status === row.status) {
        return;
    }

    message.value = '';
    savingId.value = row.clientId;

    const result = await props.request('patch', bookingUrl(row), { status });

    savingId.value = null;

    if (result.status === 200) {
        applyListing(result.data);
    } else {
        message.value = failureText(result, 'Не удалось сохранить статус. Попробуйте ещё раз.');
    }
};

const notesEditing = ref(null);
const notesDraft = ref('');

const startNotes = (row) => {
    notesEditing.value = row.clientId;
    notesDraft.value = row.notes ?? '';
};

const saveNotes = async (row) => {
    message.value = '';
    savingId.value = row.clientId;

    const result = await props.request('patch', bookingUrl(row), { status: row.status, notes: notesDraft.value });

    savingId.value = null;

    if (result.status === 200) {
        notesEditing.value = null;
        applyListing(result.data);
    } else {
        message.value = failureText(result, 'Не удалось сохранить заметку. Попробуйте ещё раз.');
    }
};

/* ---------- Запись клиента: поиск ---------- */

const searchInput = ref(null);
const term = ref('');
const results = ref([]);
const searching = ref(false);
const searched = ref(false);
const adding = ref(false);
let searchTimer = null;
let searchId = 0;

const runSearch = async () => {
    const id = ++searchId;
    searching.value = true;

    const result = await props.request('get', `/clients/search?q=${encodeURIComponent(term.value.trim())}`);

    if (id !== searchId) {
        return;
    }

    searching.value = false;

    if (result.status === 200) {
        results.value = result.data.clients;
        searched.value = true;
    } else {
        message.value = 'Не удалось выполнить поиск. Попробуйте ещё раз.';
    }
};

watch(term, () => {
    clearTimeout(searchTimer);
    searchId += 1;
    searched.value = false;

    if (term.value.trim() === '') {
        results.value = [];
        searching.value = false;

        return;
    }

    searchTimer = setTimeout(runSearch, 300);
});

const focusSearch = async () => {
    await nextTick();
    searchInput.value?.$el?.focus();
};

/** Записывает клиента и показывает обновлённый список. Возвращает, получилось ли. */
const addClient = async (clientId) => {
    message.value = '';
    adding.value = true;

    const result = await props.request('post', `/events/${props.event.id}/clients`, { client_id: clientId });

    adding.value = false;

    if (result.status === 201) {
        applyListing(result.data);
        term.value = '';
        results.value = [];
        creating.value = false;
        focusSearch();

        return true;
    }

    message.value = failureText(result, 'Не удалось записать клиента. Попробуйте ещё раз.');

    return false;
};

/* ---------- Запись клиента: новый клиент ---------- */

const creating = ref(false);
const newClient = ref({ last_name: '', first_name: '', phone: '' });
const createErrors = ref({});
const duplicates = ref([]);
const confirmDuplicate = ref(false);
const creatingBusy = ref(false);
let duplicatesTimer = null;
let duplicatesId = 0;

/** То, что вводили в поиске, подставляется в форму: слова — в фамилию и имя, номер — в телефон. */
const startCreating = () => {
    const text = term.value.trim();
    const hasLetters = /\p{L}/u.test(text);
    const [lastName = '', firstName = ''] = hasLetters ? text.split(/\s+/) : [];

    newClient.value = {
        last_name: lastName,
        first_name: firstName,
        phone: !hasLetters && text.replace(/\D/g, '').length >= 7 ? text : '',
    };
    createErrors.value = {};
    duplicates.value = [];
    confirmDuplicate.value = false;
    creating.value = true;
};

const cancelCreating = () => {
    creating.value = false;
    focusSearch();
};

const checkDuplicates = async () => {
    const id = ++duplicatesId;

    if (newClient.value.phone.replace(/\D/g, '').length < 7) {
        duplicates.value = [];
        confirmDuplicate.value = false;

        return;
    }

    const result = await props.request('get', `/clients/duplicates?phone=${encodeURIComponent(newClient.value.phone)}`);

    if (result.status !== 200 || id !== duplicatesId) {
        return;
    }

    duplicates.value = result.data.duplicates;

    if (duplicates.value.length === 0) {
        confirmDuplicate.value = false;
    }
};

watch(
    () => newClient.value.phone,
    () => {
        clearTimeout(duplicatesTimer);
        duplicatesTimer = setTimeout(checkDuplicates, 400);
    },
);

/** Сервер присылает по каждому полю список ошибок, в форме достаточно первой. */
const firstErrors = (errors) => Object.fromEntries(Object.entries(errors).map(([field, list]) => [field, list[0]]));

const createClient = async () => {
    message.value = '';
    createErrors.value = {};
    creatingBusy.value = true;

    const created = await props.request('post', '/clients', {
        ...newClient.value,
        confirm_duplicate: confirmDuplicate.value,
    });

    if (created.status !== 201) {
        creatingBusy.value = false;

        if (created.status === 422 && created.data?.errors) {
            createErrors.value = firstErrors(created.data.errors);
            await checkDuplicates();
        } else {
            message.value = failureText(created, 'Не удалось создать клиента. Попробуйте ещё раз.');
        }

        return;
    }

    const booked = await addClient(created.data.client.id);

    creatingBusy.value = false;

    if (!booked) {
        // Клиент уже создан: оставляем его в поиске, чтобы записать, когда причина отпадёт.
        creating.value = false;
        term.value = created.data.client.name;
        message.value = `Клиент добавлен в список клиентов, но на занятие не записан. ${message.value}`;
    }
};

const bookDuplicate = async (duplicate) => {
    await addClient(duplicate.id);
};

onBeforeUnmount(() => {
    clearTimeout(searchTimer);
    clearTimeout(duplicatesTimer);
});
</script>

<template>
    <div class="flex min-h-0 flex-1 flex-col">
        <div class="space-y-5 overflow-y-auto px-6 py-5">
            <p class="text-sm font-medium text-ink" role="status">
                {{ capacityLabel }}<span v-if="isFull" class="text-flag"> — мест нет</span>
            </p>

            <p v-if="loading" class="text-sm text-muted">Загрузка…</p>

            <ul v-else-if="bookings.length" class="divide-y divide-line rounded-md border border-line" aria-label="Клиенты занятия">
                <li v-for="row in bookings" :key="row.clientId" class="flex flex-wrap items-start justify-between gap-x-4 gap-y-2 px-4 py-3">
                    <div class="min-w-0 flex-1">
                        <p class="text-sm">
                            <a
                                :href="`/clients/${row.clientId}`"
                                target="_blank"
                                rel="noopener"
                                class="font-medium text-ink underline-offset-4 hover:underline"
                            >
                                {{ row.name }}
                            </a>
                            <span v-if="row.isDeleted" class="text-muted"> (удалён)</span>
                        </p>
                        <p class="text-sm text-muted">{{ row.phone }}</p>

                        <p v-if="row.notes && notesEditing !== row.clientId" class="mt-1 whitespace-pre-line text-sm text-ink">
                            {{ row.notes }}
                        </p>

                        <form v-if="notesEditing === row.clientId" class="mt-2 flex flex-wrap items-center gap-2" @submit.prevent="saveNotes(row)">
                            <label :for="`notes-${row.clientId}`" class="sr-only">Заметка: {{ row.name }}</label>
                            <TextInput :id="`notes-${row.clientId}`" v-model="notesDraft" autocomplete="off" maxlength="2000" class="min-w-0 flex-1" />
                            <button
                                type="submit"
                                class="rounded-md bg-sea-600 px-3 py-2 text-sm font-medium text-white hover:bg-sea-700 disabled:opacity-60"
                                :disabled="savingId === row.clientId"
                            >
                                Сохранить
                            </button>
                            <button type="button" class="text-sm text-muted hover:text-ink" @click="notesEditing = null">Отмена</button>
                        </form>
                        <button
                            v-else-if="!isLocked(row)"
                            type="button"
                            class="mt-1 text-sm text-muted underline-offset-4 hover:text-ink hover:underline"
                            @click="startNotes(row)"
                        >
                            {{ row.notes ? 'Изменить заметку' : 'Добавить заметку' }}
                        </button>
                    </div>

                    <div>
                        <label :for="`status-${row.clientId}`" class="sr-only">Статус: {{ row.name }}</label>
                        <SelectInput
                            :id="`status-${row.clientId}`"
                            :model-value="row.status"
                            :disabled="isLocked(row) || savingId === row.clientId"
                            class="w-40"
                            @update:model-value="changeStatus(row, $event)"
                        >
                            <option
                                v-for="status in attendanceStatuses"
                                :key="status.value"
                                :value="status.value"
                                :disabled="isOptionDisabled(status, row)"
                            >
                                {{ status.label }}
                            </option>
                        </SelectInput>
                    </div>
                </li>
            </ul>

            <p v-else class="rounded-md border border-dashed border-line px-4 py-6 text-center text-sm text-muted">
                Пока никого не записали.
            </p>

            <p v-if="event.isCancelled" class="text-sm text-muted">Занятие отменено, записать клиентов нельзя.</p>

            <section v-else-if="canAdd" class="rounded-md border border-line bg-surface p-4" aria-labelledby="add-client-heading">
                <h3 id="add-client-heading" class="text-sm font-medium text-ink">Записать клиента</h3>

                <p v-if="isFull" class="mt-2 text-sm text-amber-900">
                    Свободных мест нет. Увеличьте лимит мест в данных занятия или отметьте кого-то из записанных как «Отменил».
                </p>

                <form v-else-if="creating" class="mt-3 space-y-4" novalidate @submit.prevent="createClient">
                    <div class="grid gap-4 sm:grid-cols-2">
                        <FormField id="new-last-name" label="Фамилия" :error="createErrors.last_name">
                            <TextInput id="new-last-name" v-model="newClient.last_name" autocomplete="off" required :invalid="Boolean(createErrors.last_name)" />
                        </FormField>
                        <FormField id="new-first-name" label="Имя" :error="createErrors.first_name">
                            <TextInput id="new-first-name" v-model="newClient.first_name" autocomplete="off" required :invalid="Boolean(createErrors.first_name)" />
                        </FormField>
                    </div>

                    <FormField id="new-phone" label="Телефон" :error="createErrors.phone">
                        <TextInput id="new-phone" v-model="newClient.phone" type="tel" autocomplete="off" required :invalid="Boolean(createErrors.phone)" />
                    </FormField>

                    <div v-if="duplicates.length" role="alert" class="rounded-md border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-900">
                        <p class="font-medium">
                            {{ duplicates.length === 1 ? 'Клиент с таким телефоном уже есть:' : 'Клиенты с таким телефоном уже есть:' }}
                        </p>
                        <ul class="mt-1.5 space-y-1.5">
                            <li v-for="duplicate in duplicates" :key="duplicate.id" class="flex flex-wrap items-center gap-x-3 gap-y-1">
                                <span class="font-medium">{{ duplicate.name }}</span>
                                <span class="text-amber-800">{{ duplicate.phone }}</span>
                                <button
                                    type="button"
                                    class="rounded-md border border-amber-400 bg-white px-2.5 py-1 font-medium text-amber-900 hover:bg-amber-100 disabled:opacity-60"
                                    :disabled="adding || creatingBusy || listedIds.has(duplicate.id)"
                                    @click="bookDuplicate(duplicate)"
                                >
                                    {{ listedIds.has(duplicate.id) ? 'Уже в списке' : 'Записать этого клиента' }}
                                </button>
                            </li>
                        </ul>
                        <label class="mt-3 flex items-start gap-2">
                            <input v-model="confirmDuplicate" type="checkbox" class="mt-0.5 size-4 rounded border-line accent-sea-600" />
                            Это другой человек (например, родственник с общим номером), создать нового
                        </label>
                    </div>

                    <div class="flex items-center gap-4">
                        <button
                            type="submit"
                            class="rounded-md bg-sea-600 px-4 py-2 text-sm font-medium text-white hover:bg-sea-700 disabled:cursor-wait disabled:opacity-60"
                            :disabled="creatingBusy"
                        >
                            Создать и записать
                        </button>
                        <button type="button" class="text-sm text-muted hover:text-ink" @click="cancelCreating">Отмена</button>
                    </div>
                </form>

                <div v-else class="mt-3">
                    <label for="client-search" class="sr-only">Найти клиента</label>
                    <TextInput
                        id="client-search"
                        ref="searchInput"
                        v-model="term"
                        type="search"
                        autocomplete="off"
                        placeholder="Фамилия, имя или телефон клиента"
                        @keydown.enter.prevent
                    />

                    <p v-if="searching" class="mt-2 text-sm text-muted" role="status">Поиск…</p>

                    <ul v-else-if="results.length" class="mt-2 divide-y divide-line rounded-md border border-line bg-white" aria-label="Найденные клиенты">
                        <li v-for="client in results" :key="client.id" class="flex items-center justify-between gap-3 px-3 py-2 text-sm">
                            <span class="min-w-0">
                                <span class="font-medium text-ink">{{ client.name }}</span>
                                <span class="text-muted"> · {{ client.phone }}</span>
                            </span>
                            <span v-if="listedIds.has(client.id)" class="shrink-0 text-muted">Уже в списке</span>
                            <button
                                v-else
                                type="button"
                                class="shrink-0 rounded-md border border-line bg-white px-3 py-1.5 font-medium text-ink hover:bg-surface disabled:opacity-60"
                                :disabled="adding"
                                :aria-label="`Записать: ${client.name}`"
                                @click="addClient(client.id)"
                            >
                                Записать
                            </button>
                        </li>
                    </ul>

                    <p v-else-if="searched" class="mt-2 text-sm text-muted">Такого клиента ещё нет.</p>

                    <button
                        type="button"
                        class="mt-3 text-sm font-medium text-sea-700 underline-offset-4 hover:underline"
                        @click="startCreating"
                    >
                        Создать нового клиента{{ term.trim() ? ` «${term.trim()}»` : '' }}
                    </button>
                </div>
            </section>

            <p v-if="message" role="alert" class="text-sm text-flag">{{ message }}</p>
        </div>

        <div v-if="event.status === 'planned' && event.canUpdate" class="flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-line px-6 py-4">
            <button
                type="button"
                class="rounded-md border border-line bg-white px-4 py-2 text-sm font-medium text-ink hover:bg-surface"
                @click="emit('mark-done')"
            >
                Занятие проведено
            </button>
            <p v-if="unmarkedCount" class="text-sm text-muted">Посещение не отмечено у клиентов: {{ unmarkedCount }}.</p>
        </div>
    </div>
</template>

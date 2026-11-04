<script setup>
import { Link, usePage } from '@inertiajs/vue3';
import { computed, ref } from 'vue';
import AppIcon from '../../components/AppIcon.vue';
import SelectInput from '../../components/SelectInput.vue';
import TextInput from '../../components/TextInput.vue';
import AppLayout from '../../layouts/AppLayout.vue';

const props = defineProps({
    /** Снаряжение: { id, name, inventoryNumber, size, status, statusLabel, locationId, locationName, instructorId, instructorName }. */
    equipment: { type: Array, required: true },
    /** Все локации: { id, name, isActive }. */
    locations: { type: Array, required: true },
    /** Все инструкторы: { id, name, isActive }. */
    instructors: { type: Array, required: true },
    statuses: { type: Array, required: true },
});

const NONE = 'none';

/** Фильтр по локации или инструктору можно открыть ссылкой: /equipment?location=3, /equipment?instructor=5. */
const query = new URLSearchParams(usePage().url.split('?')[1] ?? '');
const fromQuery = (key, options) => {
    const value = query.get(key);

    if (value === NONE) {
        return NONE;
    }

    return options.find((option) => String(option.id) === value)?.id ?? '';
};

const search = ref('');
const locationFilter = ref(fromQuery('location', props.locations));
const instructorFilter = ref(fromQuery('instructor', props.instructors));
const statusFilter = ref('');

const matches = (value, filter) => filter === '' || (filter === NONE ? value === null : value === filter);

const visibleEquipment = computed(() => {
    const term = search.value.trim().toLowerCase();

    return props.equipment.filter(
        (item) =>
            (term === '' || [item.name, item.inventoryNumber, item.size].some((field) => field?.toLowerCase().includes(term))) &&
            matches(item.locationId, locationFilter.value) &&
            matches(item.instructorId, instructorFilter.value) &&
            (statusFilter.value === '' || item.status === statusFilter.value),
    );
});

const isFiltered = computed(() => search.value.trim() !== '' || locationFilter.value !== '' || instructorFilter.value !== '' || statusFilter.value !== '');

const resetFilters = () => {
    search.value = '';
    locationFilter.value = '';
    instructorFilter.value = '';
    statusFilter.value = '';
};

const statusClass = (status) =>
    ({
        in_use: 'bg-sea-50 text-sea-700',
        repair: 'bg-amber-50 text-amber-800',
        written_off: 'bg-slate-100 text-muted',
    })[status];
</script>

<template>
    <AppLayout title="Реестр снаряжения">
        <template #actions>
            <Link
                href="/equipment/create"
                class="inline-flex items-center rounded-md bg-sea-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-sea-700"
            >
                <AppIcon name="plus" />
                <span class="ml-1.5">Добавить снаряжение</span>
            </Link>
        </template>

        <p class="max-w-2xl text-sm leading-6 text-muted">
            Здесь учитывается снаряжение школы: где оно хранится и за каким инструктором закреплено. Списанное снаряжение остаётся в
            реестре, чтобы не терялась история.
        </p>

        <div v-if="equipment.length === 0" class="mt-6 rounded-lg border border-dashed border-line bg-white px-6 py-12 text-center">
            <p class="text-base font-medium text-ink">Реестр пока пуст</p>
            <p class="mx-auto mt-2 max-w-md text-sm leading-6 text-muted">Добавьте первое снаряжение, чтобы вести его учёт.</p>
        </div>

        <template v-else>
            <div class="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <div>
                    <label for="equipment-search" class="sr-only">Поиск по названию, номеру или размеру</label>
                    <TextInput id="equipment-search" v-model="search" type="search" placeholder="Название, номер, размер" autocomplete="off" />
                </div>
                <div>
                    <label for="equipment-location" class="sr-only">Локация</label>
                    <SelectInput id="equipment-location" v-model="locationFilter">
                        <option value="">Все локации</option>
                        <option :value="NONE">Без локации</option>
                        <option v-for="location in locations" :key="location.id" :value="location.id">
                            {{ location.name }}{{ location.isActive ? '' : ' (скрыта)' }}
                        </option>
                    </SelectInput>
                </div>
                <div>
                    <label for="equipment-instructor" class="sr-only">Инструктор</label>
                    <SelectInput id="equipment-instructor" v-model="instructorFilter">
                        <option value="">Все инструкторы</option>
                        <option :value="NONE">Не закреплено</option>
                        <option v-for="instructor in instructors" :key="instructor.id" :value="instructor.id">
                            {{ instructor.name }}{{ instructor.isActive ? '' : ' (отключён)' }}
                        </option>
                    </SelectInput>
                </div>
                <div>
                    <label for="equipment-status" class="sr-only">Состояние</label>
                    <SelectInput id="equipment-status" v-model="statusFilter">
                        <option value="">Любое состояние</option>
                        <option v-for="status in statuses" :key="status.value" :value="status.value">{{ status.label }}</option>
                    </SelectInput>
                </div>
            </div>

            <p class="mt-3 text-sm text-muted">
                Показано {{ visibleEquipment.length }} из {{ equipment.length }}
                <button v-if="isFiltered" type="button" class="ml-2 text-sea-700 hover:underline" @click="resetFilters">Сбросить фильтры</button>
            </p>

            <div class="mt-3 overflow-hidden rounded-lg border border-line bg-white">
                <table class="w-full text-left text-sm">
                    <thead class="hidden border-b border-line bg-surface text-muted sm:table-header-group">
                        <tr>
                            <th scope="col" class="px-4 py-2.5 font-medium">Снаряжение</th>
                            <th scope="col" class="hidden px-4 py-2.5 font-medium md:table-cell">Локация</th>
                            <th scope="col" class="hidden px-4 py-2.5 font-medium md:table-cell">Инструктор</th>
                            <th scope="col" class="px-4 py-2.5 font-medium">Состояние</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-line">
                        <tr v-for="item in visibleEquipment" :key="item.id" class="flex flex-col gap-1 px-4 py-3 sm:table-row sm:p-0">
                            <td class="sm:px-4 sm:py-3">
                                <Link
                                    :href="`/equipment/${item.id}/edit`"
                                    class="font-medium underline-offset-4 hover:text-sea-700 hover:underline"
                                    :class="item.status === 'written_off' ? 'text-muted' : 'text-ink'"
                                >
                                    {{ item.name }}
                                </Link>
                                <div class="text-xs text-muted">
                                    <span v-if="item.inventoryNumber">№ {{ item.inventoryNumber }}</span>
                                    <span v-if="item.inventoryNumber && item.size"> · </span>
                                    <span v-if="item.size">размер {{ item.size }}</span>
                                </div>
                                <div class="text-xs text-muted md:hidden">
                                    {{ [item.locationName, item.instructorName].filter(Boolean).join(' · ') }}
                                </div>
                            </td>
                            <td class="hidden px-4 py-3 md:table-cell" :class="item.locationName ? 'text-ink' : 'text-muted'">
                                {{ item.locationName ?? '—' }}
                            </td>
                            <td class="hidden px-4 py-3 md:table-cell" :class="item.instructorName ? 'text-ink' : 'text-muted'">
                                {{ item.instructorName ?? '—' }}
                            </td>
                            <td class="sm:px-4 sm:py-3">
                                <span class="inline-block rounded px-2 py-0.5 text-xs" :class="statusClass(item.status)">{{ item.statusLabel }}</span>
                            </td>
                        </tr>
                        <tr v-if="visibleEquipment.length === 0">
                            <td colspan="4" class="block px-4 py-6 text-sm text-muted sm:table-cell">Под выбранные фильтры ничего не подходит.</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </template>
    </AppLayout>
</template>

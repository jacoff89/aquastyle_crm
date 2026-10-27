<script setup>
import { Link, router } from '@inertiajs/vue3';
import { computed, onBeforeUnmount, ref, watch } from 'vue';
import AppIcon from '../../components/AppIcon.vue';
import FormField from '../../components/FormField.vue';
import TextInput from '../../components/TextInput.vue';
import AppLayout from '../../layouts/AppLayout.vue';

const props = defineProps({
    clients: { type: Object, required: true },
    filters: { type: Object, required: true },
});

const search = ref(props.filters.search);
const isSearching = computed(() => props.filters.search !== '');

/**
 * Адрес списка с параметрами; значения по умолчанию в адрес не попадают.
 */
const listUrl = (overrides = {}) => {
    const params = { ...props.filters, ...overrides };
    const query = new URLSearchParams();

    if (params.search) {
        query.set('search', params.search);
    }
    if (params.sort !== 'name') {
        query.set('sort', params.sort);
    }
    if (params.direction !== 'asc') {
        query.set('direction', params.direction);
    }

    const queryString = query.toString();

    return queryString ? `/clients?${queryString}` : '/clients';
};

let searchTimer = null;

watch(search, (value) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
        const term = value.trim();

        if (term !== props.filters.search) {
            router.get(listUrl({ search: term }), {}, { preserveState: true, replace: true });
        }
    }, 300);
});

onBeforeUnmount(() => clearTimeout(searchTimer));

const sortHref = (key) => {
    const isCurrent = props.filters.sort === key;

    return listUrl({ sort: key, direction: isCurrent && props.filters.direction === 'asc' ? 'desc' : 'asc' });
};

const ariaSort = (key) => {
    if (props.filters.sort !== key) {
        return 'none';
    }

    return props.filters.direction === 'asc' ? 'ascending' : 'descending';
};

const arrow = (key) => {
    if (props.filters.sort !== key) {
        return '';
    }

    return props.filters.direction === 'asc' ? '↑' : '↓';
};
</script>

<template>
    <AppLayout title="Клиенты">
        <template #actions>
            <Link
                href="/clients/create"
                class="inline-flex items-center rounded-md bg-sea-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-sea-700"
            >
                <AppIcon name="plus" />
                <span class="ml-1.5">Добавить клиента</span>
            </Link>
        </template>

        <div class="max-w-md">
            <FormField id="search" label="Поиск" hint="По фамилии, имени, телефону или email.">
                <TextInput id="search" v-model="search" type="search" autocomplete="off" placeholder="Например: Иванов или 912" />
            </FormField>
        </div>

        <div
            v-if="clients.total === 0"
            class="mt-6 rounded-lg border border-dashed border-line bg-white px-6 py-12 text-center"
        >
            <template v-if="isSearching">
                <p class="text-base font-medium text-ink">Никого не нашли</p>
                <p class="mx-auto mt-2 max-w-md text-sm leading-6 text-muted">
                    По запросу «{{ filters.search }}» клиентов нет. Проверьте написание или поищите по части телефона.
                </p>
                <Link :href="listUrl({ search: '' })" class="mt-4 inline-block text-sm text-sea-700 hover:underline">
                    Сбросить поиск
                </Link>
            </template>
            <template v-else>
                <p class="text-base font-medium text-ink">Клиентов пока нет</p>
                <p class="mx-auto mt-2 max-w-md text-sm leading-6 text-muted">
                    Добавьте первого клиента, чтобы записывать его на занятия.
                </p>
            </template>
        </div>

        <template v-else>
            <div class="mt-6 overflow-hidden rounded-lg border border-line bg-white">
                <table class="w-full text-left text-sm">
                    <thead class="hidden border-b border-line bg-surface text-muted sm:table-header-group">
                        <tr>
                            <th scope="col" class="px-4 py-2.5 font-medium" :aria-sort="ariaSort('name')">
                                <Link :href="sortHref('name')" class="hover:text-ink">Клиент {{ arrow('name') }}</Link>
                            </th>
                            <th scope="col" class="px-4 py-2.5 font-medium" :aria-sort="ariaSort('phone')">
                                <Link :href="sortHref('phone')" class="hover:text-ink">Телефон {{ arrow('phone') }}</Link>
                            </th>
                            <th scope="col" class="hidden px-4 py-2.5 font-medium md:table-cell">Email</th>
                            <th scope="col" class="hidden px-4 py-2.5 font-medium lg:table-cell" :aria-sort="ariaSort('created')">
                                <Link :href="sortHref('created')" class="hover:text-ink">Добавлен {{ arrow('created') }}</Link>
                            </th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-line">
                        <tr v-for="client in clients.data" :key="client.id" class="flex flex-col px-4 py-3 sm:table-row sm:p-0">
                            <td class="sm:px-4 sm:py-3">
                                <Link
                                    :href="`/clients/${client.id}`"
                                    class="font-medium text-ink underline-offset-4 hover:text-sea-700 hover:underline"
                                >
                                    {{ client.name }}
                                </Link>
                            </td>
                            <td class="text-muted sm:px-4 sm:py-3">{{ client.phone }}</td>
                            <td class="hidden px-4 py-3 text-muted md:table-cell">{{ client.email || '—' }}</td>
                            <td class="hidden px-4 py-3 text-muted lg:table-cell">{{ client.createdAtLabel }}</td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <div class="mt-4 flex flex-wrap items-center justify-between gap-3 text-sm text-muted">
                <p>Показаны {{ clients.from }}–{{ clients.to }} из {{ clients.total }}</p>
                <nav v-if="clients.lastPage > 1" class="flex items-center gap-2" aria-label="Страницы списка">
                    <Link
                        v-if="clients.previousPageUrl"
                        :href="clients.previousPageUrl"
                        class="rounded-md border border-line bg-white px-3 py-1.5 text-ink hover:bg-surface"
                    >
                        ← Назад
                    </Link>
                    <span>Страница {{ clients.currentPage }} из {{ clients.lastPage }}</span>
                    <Link
                        v-if="clients.nextPageUrl"
                        :href="clients.nextPageUrl"
                        class="rounded-md border border-line bg-white px-3 py-1.5 text-ink hover:bg-surface"
                    >
                        Вперёд →
                    </Link>
                </nav>
            </div>
        </template>
    </AppLayout>
</template>

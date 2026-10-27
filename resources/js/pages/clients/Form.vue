<script setup>
import { Link, useForm } from '@inertiajs/vue3';
import { computed, onBeforeUnmount, ref, watch } from 'vue';
import FormField from '../../components/FormField.vue';
import PrimaryButton from '../../components/PrimaryButton.vue';
import TextArea from '../../components/TextArea.vue';
import TextInput from '../../components/TextInput.vue';
import AppLayout from '../../layouts/AppLayout.vue';

const props = defineProps({
    client: { type: Object, default: null },
});

const isEditing = computed(() => props.client !== null);
const title = computed(() => (isEditing.value ? `${props.client.lastName} ${props.client.firstName}` : 'Новый клиент'));

const form = useForm({
    last_name: props.client?.lastName ?? '',
    first_name: props.client?.firstName ?? '',
    middle_name: props.client?.middleName ?? '',
    phone: props.client?.phone ?? '',
    email: props.client?.email ?? '',
    birth_date: props.client?.birthDate ?? '',
    notes: props.client?.notes ?? '',
    confirm_duplicate: false,
});

/**
 * Клиенты с таким же телефоном. Список приходит с сервера, пока человек вводит номер,
 * а сервер всё равно не сохранит дубль без подтверждения.
 */
const duplicates = ref([]);
let checkTimer = null;
let checkId = 0;

const checkDuplicates = async () => {
    const id = ++checkId;
    const digits = form.phone.replace(/\D/g, '');

    if (digits.length < 7) {
        duplicates.value = [];
        form.confirm_duplicate = false;

        return;
    }

    const query = new URLSearchParams({ phone: form.phone });

    if (isEditing.value) {
        query.set('except', props.client.id);
    }

    try {
        const response = await fetch(`/clients/duplicates?${query}`, { headers: { Accept: 'application/json' } });

        if (!response.ok || id !== checkId) {
            return;
        }

        duplicates.value = (await response.json()).duplicates;

        if (duplicates.value.length === 0) {
            form.confirm_duplicate = false;
        }
    } catch {
        // Без проверки форму всё равно можно отправить: сервер сам остановит дубль.
    }
};

watch(
    () => form.phone,
    () => {
        clearTimeout(checkTimer);
        checkTimer = setTimeout(checkDuplicates, 400);
    },
    { immediate: isEditing.value },
);

onBeforeUnmount(() => clearTimeout(checkTimer));

const submit = () => {
    const options = { onError: checkDuplicates };

    if (isEditing.value) {
        form.put(`/clients/${props.client.id}`, options);
    } else {
        form.post('/clients', options);
    }
};
</script>

<template>
    <AppLayout :title="title">
        <form class="max-w-2xl space-y-8" novalidate @submit.prevent="submit">
            <section class="space-y-5 rounded-lg border border-line bg-white p-6" aria-labelledby="client-heading">
                <h2 id="client-heading" class="text-lg font-semibold">Клиент</h2>

                <div class="grid gap-5 sm:grid-cols-3">
                    <FormField id="last_name" label="Фамилия" :error="form.errors.last_name">
                        <TextInput
                            id="last_name"
                            v-model="form.last_name"
                            autocomplete="off"
                            required
                            :invalid="Boolean(form.errors.last_name)"
                        />
                    </FormField>

                    <FormField id="first_name" label="Имя" :error="form.errors.first_name">
                        <TextInput
                            id="first_name"
                            v-model="form.first_name"
                            autocomplete="off"
                            required
                            :invalid="Boolean(form.errors.first_name)"
                        />
                    </FormField>

                    <FormField id="middle_name" label="Отчество" :error="form.errors.middle_name">
                        <TextInput
                            id="middle_name"
                            v-model="form.middle_name"
                            autocomplete="off"
                            :invalid="Boolean(form.errors.middle_name)"
                        />
                    </FormField>
                </div>

                <FormField id="phone" label="Телефон" hint="По телефону ищем клиента и находим повторные записи." :error="form.errors.phone">
                    <TextInput
                        id="phone"
                        v-model="form.phone"
                        type="tel"
                        autocomplete="off"
                        required
                        :invalid="Boolean(form.errors.phone)"
                    />
                </FormField>

                <div
                    v-if="duplicates.length"
                    role="alert"
                    class="rounded-md border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-900"
                >
                    <p class="font-medium">
                        {{ duplicates.length === 1 ? 'Клиент с таким телефоном уже есть:' : 'Клиенты с таким телефоном уже есть:' }}
                    </p>
                    <ul class="mt-1.5 space-y-1">
                        <li v-for="duplicate in duplicates" :key="duplicate.id">
                            <Link
                                :href="`/clients/${duplicate.id}`"
                                target="_blank"
                                class="font-medium underline underline-offset-4 hover:text-amber-950"
                            >
                                {{ duplicate.name }}
                            </Link>
                            <span class="text-amber-800"> · {{ duplicate.phone }}</span>
                        </li>
                    </ul>
                    <label class="mt-3 flex items-start gap-2">
                        <input
                            v-model="form.confirm_duplicate"
                            type="checkbox"
                            class="mt-0.5 size-4 rounded border-line accent-sea-600"
                        />
                        Это другой человек (например, родственник с общим номером), сохранить всё равно
                    </label>
                </div>

                <div class="grid gap-5 sm:grid-cols-2">
                    <FormField id="email" label="Email" :error="form.errors.email">
                        <TextInput
                            id="email"
                            v-model="form.email"
                            type="email"
                            autocomplete="off"
                            :invalid="Boolean(form.errors.email)"
                        />
                    </FormField>

                    <FormField id="birth_date" label="Дата рождения" :error="form.errors.birth_date">
                        <TextInput
                            id="birth_date"
                            v-model="form.birth_date"
                            type="date"
                            min="1900-01-02"
                            :invalid="Boolean(form.errors.birth_date)"
                        />
                    </FormField>
                </div>

                <FormField id="notes" label="Заметки" :error="form.errors.notes">
                    <TextArea id="notes" v-model="form.notes" :invalid="Boolean(form.errors.notes)" />
                </FormField>
            </section>

            <div class="flex items-center gap-4">
                <PrimaryButton :processing="form.processing">
                    {{ isEditing ? 'Сохранить изменения' : 'Добавить клиента' }}
                </PrimaryButton>
                <Link :href="isEditing ? `/clients/${client.id}` : '/clients'" class="text-sm text-muted hover:text-ink">
                    Отмена
                </Link>
            </div>
        </form>
    </AppLayout>
</template>

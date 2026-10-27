<script setup>
import { Head, Link, useForm } from '@inertiajs/vue3';
import FormField from '../../components/FormField.vue';
import PrimaryButton from '../../components/PrimaryButton.vue';
import StatusMessage from '../../components/StatusMessage.vue';
import TextInput from '../../components/TextInput.vue';
import GuestLayout from '../../layouts/GuestLayout.vue';

defineProps({
    status: { type: String, default: '' },
});

const form = useForm({
    email: '',
    password: '',
    remember: false,
});

const submit = () => {
    form.post('/login', {
        onFinish: () => form.reset('password'),
    });
};
</script>

<template>
    <Head title="Вход" />

    <GuestLayout title="Вход в систему" description="Учётные записи создаёт администратор дайв-центра.">
        <StatusMessage :message="status" class="mb-6" />

        <form class="space-y-5" novalidate @submit.prevent="submit">
            <FormField id="email" label="Email" :error="form.errors.email">
                <TextInput
                    id="email"
                    v-model="form.email"
                    type="email"
                    autocomplete="username"
                    autofocus
                    required
                    :invalid="Boolean(form.errors.email)"
                />
            </FormField>

            <FormField id="password" label="Пароль" :error="form.errors.password">
                <TextInput
                    id="password"
                    v-model="form.password"
                    type="password"
                    autocomplete="current-password"
                    required
                    :invalid="Boolean(form.errors.password)"
                />
            </FormField>

            <div class="flex items-center justify-between gap-4">
                <label class="flex items-center gap-2 text-sm text-ink">
                    <input v-model="form.remember" type="checkbox" class="size-4 rounded border-line accent-sea-600" />
                    Запомнить меня
                </label>
                <Link href="/forgot-password" class="text-sm text-sea-700 underline-offset-4 hover:underline">
                    Забыли пароль?
                </Link>
            </div>

            <PrimaryButton :processing="form.processing" class="w-full">Войти</PrimaryButton>
        </form>
    </GuestLayout>
</template>

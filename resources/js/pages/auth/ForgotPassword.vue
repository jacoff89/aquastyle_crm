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
});

const submit = () => {
    form.post('/forgot-password');
};
</script>

<template>
    <Head title="Сброс пароля" />

    <GuestLayout title="Сброс пароля" description="Укажите email, с которым входите в систему. Пришлём ссылку для нового пароля.">
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

            <PrimaryButton :processing="form.processing" class="w-full">Отправить ссылку</PrimaryButton>

            <p class="text-center text-sm">
                <Link href="/login" class="text-sea-700 underline-offset-4 hover:underline">Вернуться ко входу</Link>
            </p>
        </form>
    </GuestLayout>
</template>

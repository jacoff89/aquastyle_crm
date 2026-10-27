<script setup>
import { Head, useForm } from '@inertiajs/vue3';
import FormField from '../../components/FormField.vue';
import PrimaryButton from '../../components/PrimaryButton.vue';
import TextInput from '../../components/TextInput.vue';
import GuestLayout from '../../layouts/GuestLayout.vue';

const props = defineProps({
    email: { type: String, default: '' },
    token: { type: String, required: true },
});

const form = useForm({
    token: props.token,
    email: props.email,
    password: '',
    password_confirmation: '',
});

const submit = () => {
    form.post('/reset-password', {
        onFinish: () => form.reset('password', 'password_confirmation'),
    });
};
</script>

<template>
    <Head title="Новый пароль" />

    <GuestLayout title="Новый пароль">
        <form class="space-y-5" novalidate @submit.prevent="submit">
            <FormField id="email" label="Email" :error="form.errors.email">
                <TextInput
                    id="email"
                    v-model="form.email"
                    type="email"
                    autocomplete="username"
                    required
                    :invalid="Boolean(form.errors.email)"
                />
            </FormField>

            <FormField id="password" label="Новый пароль" hint="Не короче 8 символов." :error="form.errors.password">
                <TextInput
                    id="password"
                    v-model="form.password"
                    type="password"
                    autocomplete="new-password"
                    autofocus
                    required
                    :invalid="Boolean(form.errors.password)"
                />
            </FormField>

            <FormField id="password_confirmation" label="Повторите пароль">
                <TextInput
                    id="password_confirmation"
                    v-model="form.password_confirmation"
                    type="password"
                    autocomplete="new-password"
                    required
                />
            </FormField>

            <PrimaryButton :processing="form.processing" class="w-full">Сохранить пароль</PrimaryButton>
        </form>
    </GuestLayout>
</template>

<script setup>
import { useForm } from '@inertiajs/vue3';
import FormField from '../../components/FormField.vue';
import PrimaryButton from '../../components/PrimaryButton.vue';
import TextInput from '../../components/TextInput.vue';
import AppLayout from '../../layouts/AppLayout.vue';

const props = defineProps({
    profile: { type: Object, required: true },
});

const profileForm = useForm({
    name: props.profile.name,
    phone: props.profile.phone ?? '',
});

const passwordForm = useForm({
    current_password: '',
    password: '',
    password_confirmation: '',
});

const saveProfile = () => {
    profileForm.patch('/profile', { preserveScroll: true });
};

const changePassword = () => {
    passwordForm.put('/profile/password', {
        preserveScroll: true,
        onSuccess: () => passwordForm.reset(),
        onError: () => passwordForm.reset('current_password', 'password', 'password_confirmation'),
    });
};
</script>

<template>
    <AppLayout title="Профиль">
        <div class="grid max-w-4xl gap-6 lg:grid-cols-2">
            <section class="rounded-lg border border-line bg-white p-6" aria-labelledby="profile-heading">
                <h2 id="profile-heading" class="text-lg font-semibold">Личные данные</h2>
                <p class="mt-1 text-sm text-muted">{{ profile.role }}, вход по {{ profile.email }}</p>

                <form class="mt-6 space-y-5" novalidate @submit.prevent="saveProfile">
                    <FormField id="name" label="Имя" :error="profileForm.errors.name">
                        <TextInput
                            id="name"
                            v-model="profileForm.name"
                            autocomplete="name"
                            required
                            :invalid="Boolean(profileForm.errors.name)"
                        />
                    </FormField>

                    <FormField id="phone" label="Телефон" :error="profileForm.errors.phone">
                        <TextInput
                            id="phone"
                            v-model="profileForm.phone"
                            type="tel"
                            autocomplete="tel"
                            :invalid="Boolean(profileForm.errors.phone)"
                        />
                    </FormField>

                    <PrimaryButton :processing="profileForm.processing">Сохранить</PrimaryButton>
                </form>
            </section>

            <section class="rounded-lg border border-line bg-white p-6" aria-labelledby="password-heading">
                <h2 id="password-heading" class="text-lg font-semibold">Пароль</h2>
                <p class="mt-1 text-sm text-muted">Email для входа меняет администратор.</p>

                <form class="mt-6 space-y-5" novalidate @submit.prevent="changePassword">
                    <FormField id="current_password" label="Текущий пароль" :error="passwordForm.errors.current_password">
                        <TextInput
                            id="current_password"
                            v-model="passwordForm.current_password"
                            type="password"
                            autocomplete="current-password"
                            required
                            :invalid="Boolean(passwordForm.errors.current_password)"
                        />
                    </FormField>

                    <FormField
                        id="new_password"
                        label="Новый пароль"
                        hint="Не короче 8 символов."
                        :error="passwordForm.errors.password"
                    >
                        <TextInput
                            id="new_password"
                            v-model="passwordForm.password"
                            type="password"
                            autocomplete="new-password"
                            required
                            :invalid="Boolean(passwordForm.errors.password)"
                        />
                    </FormField>

                    <FormField id="new_password_confirmation" label="Повторите новый пароль">
                        <TextInput
                            id="new_password_confirmation"
                            v-model="passwordForm.password_confirmation"
                            type="password"
                            autocomplete="new-password"
                            required
                        />
                    </FormField>

                    <PrimaryButton :processing="passwordForm.processing">Изменить пароль</PrimaryButton>
                </form>
            </section>
        </div>
    </AppLayout>
</template>

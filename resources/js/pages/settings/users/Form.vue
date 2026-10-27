<script setup>
import { Link, useForm } from '@inertiajs/vue3';
import { computed } from 'vue';
import FormField from '../../../components/FormField.vue';
import PrimaryButton from '../../../components/PrimaryButton.vue';
import TextArea from '../../../components/TextArea.vue';
import TextInput from '../../../components/TextInput.vue';
import AppLayout from '../../../layouts/AppLayout.vue';

const props = defineProps({
    user: { type: Object, default: null },
    roles: { type: Array, required: true },
});

const isEditing = computed(() => props.user !== null);
const isSelf = computed(() => props.user?.isCurrentUser ?? false);

const form = useForm({
    name: props.user?.name ?? '',
    email: props.user?.email ?? '',
    phone: props.user?.phone ?? '',
    role: props.user?.role ?? 'instructor',
    is_active: props.user?.isActive ?? true,
    notes: props.user?.notes ?? '',
    password: '',
    password_confirmation: '',
});

const submit = () => {
    const options = { onFinish: () => form.reset('password', 'password_confirmation') };

    if (isEditing.value) {
        form.put(`/settings/users/${props.user.id}`, options);
    } else {
        form.post('/settings/users', options);
    }
};
</script>

<template>
    <AppLayout :title="isEditing ? user.name : 'Новый пользователь'">
        <form class="max-w-2xl space-y-8" novalidate @submit.prevent="submit">
            <section class="space-y-5 rounded-lg border border-line bg-white p-6" aria-labelledby="account-heading">
                <h2 id="account-heading" class="text-lg font-semibold">Учётная запись</h2>

                <FormField id="name" label="Имя" :error="form.errors.name">
                    <TextInput id="name" v-model="form.name" autocomplete="off" required :invalid="Boolean(form.errors.name)" />
                </FormField>

                <div class="grid gap-5 sm:grid-cols-2">
                    <FormField id="email" label="Email" hint="Логин для входа." :error="form.errors.email">
                        <TextInput
                            id="email"
                            v-model="form.email"
                            type="email"
                            autocomplete="off"
                            required
                            :invalid="Boolean(form.errors.email)"
                        />
                    </FormField>

                    <FormField id="phone" label="Телефон" :error="form.errors.phone">
                        <TextInput id="phone" v-model="form.phone" type="tel" autocomplete="off" :invalid="Boolean(form.errors.phone)" />
                    </FormField>
                </div>

                <fieldset>
                    <legend class="text-sm font-medium text-ink">Роль</legend>
                    <div class="mt-2 grid gap-3 sm:grid-cols-2">
                        <label
                            v-for="role in roles"
                            :key="role.value"
                            class="flex items-center gap-3 rounded-md border px-3 py-2.5 text-sm"
                            :class="[
                                form.role === role.value ? 'border-sea-600 bg-sea-50' : 'border-line bg-white',
                                isSelf ? 'cursor-not-allowed opacity-70' : 'cursor-pointer',
                            ]"
                        >
                            <input
                                v-model="form.role"
                                type="radio"
                                name="role"
                                :value="role.value"
                                :disabled="isSelf"
                                class="size-4 accent-sea-600"
                            />
                            {{ role.label }}
                        </label>
                    </div>
                    <p v-if="form.errors.role" class="mt-1.5 text-sm text-flag">{{ form.errors.role }}</p>
                    <p v-else-if="isSelf" class="mt-1.5 text-sm text-muted">Свою роль изменить нельзя.</p>
                </fieldset>

                <div>
                    <label class="flex items-center gap-2 text-sm" :class="isSelf ? 'cursor-not-allowed opacity-70' : ''">
                        <input
                            v-model="form.is_active"
                            type="checkbox"
                            :disabled="isSelf"
                            class="size-4 rounded border-line accent-sea-600"
                        />
                        Может входить в систему
                    </label>
                    <p v-if="form.errors.is_active" class="mt-1.5 text-sm text-flag">{{ form.errors.is_active }}</p>
                    <p v-else-if="isSelf" class="mt-1.5 text-sm text-muted">Свою учётную запись отключить нельзя.</p>
                    <p v-else class="mt-1.5 text-sm text-muted">
                        Снимите галочку, чтобы отключить учётную запись. Прошлые занятия останутся в истории.
                    </p>
                </div>

                <FormField id="notes" label="Заметки" :error="form.errors.notes">
                    <TextArea id="notes" v-model="form.notes" :invalid="Boolean(form.errors.notes)" />
                </FormField>
            </section>

            <section class="space-y-5 rounded-lg border border-line bg-white p-6" aria-labelledby="password-heading">
                <div>
                    <h2 id="password-heading" class="text-lg font-semibold">Пароль</h2>
                    <p class="mt-1 text-sm text-muted">
                        {{
                            isEditing
                                ? 'Оставьте поля пустыми, чтобы не менять пароль.'
                                : 'Сообщите пароль пользователю. Сменить его он сможет в профиле.'
                        }}
                    </p>
                </div>

                <div class="grid gap-5 sm:grid-cols-2">
                    <FormField id="password" label="Пароль" hint="Не короче 8 символов." :error="form.errors.password">
                        <TextInput
                            id="password"
                            v-model="form.password"
                            type="password"
                            autocomplete="new-password"
                            :required="!isEditing"
                            :invalid="Boolean(form.errors.password)"
                        />
                    </FormField>

                    <FormField id="password_confirmation" label="Повторите пароль">
                        <TextInput
                            id="password_confirmation"
                            v-model="form.password_confirmation"
                            type="password"
                            autocomplete="new-password"
                            :required="!isEditing"
                        />
                    </FormField>
                </div>
            </section>

            <div class="flex items-center gap-4">
                <PrimaryButton :processing="form.processing">
                    {{ isEditing ? 'Сохранить изменения' : 'Добавить пользователя' }}
                </PrimaryButton>
                <Link href="/settings/users" class="text-sm text-muted hover:text-ink">Отмена</Link>
            </div>
        </form>
    </AppLayout>
</template>

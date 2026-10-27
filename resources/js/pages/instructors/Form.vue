<script setup>
import { Link, useForm } from '@inertiajs/vue3';
import { computed } from 'vue';
import ColorPicker from '../../components/ColorPicker.vue';
import FormField from '../../components/FormField.vue';
import PrimaryButton from '../../components/PrimaryButton.vue';
import TextArea from '../../components/TextArea.vue';
import TextInput from '../../components/TextInput.vue';
import AppLayout from '../../layouts/AppLayout.vue';

const props = defineProps({
    instructor: { type: Object, default: null },
});

const isEditing = computed(() => props.instructor !== null);

const form = useForm({
    name: props.instructor?.name ?? '',
    email: props.instructor?.email ?? '',
    phone: props.instructor?.phone ?? '',
    color: props.instructor?.color ?? '#0891b2',
    is_active: props.instructor?.isActive ?? true,
    notes: props.instructor?.notes ?? '',
    password: '',
    password_confirmation: '',
});

const submit = () => {
    const options = { onFinish: () => form.reset('password', 'password_confirmation') };

    if (isEditing.value) {
        form.put(`/instructors/${props.instructor.id}`, options);
    } else {
        form.post('/instructors', options);
    }
};
</script>

<template>
    <AppLayout :title="isEditing ? instructor.name : 'Новый инструктор'">
        <form class="max-w-2xl space-y-8" novalidate @submit.prevent="submit">
            <section class="space-y-5 rounded-lg border border-line bg-white p-6" aria-labelledby="instructor-heading">
                <h2 id="instructor-heading" class="text-lg font-semibold">Инструктор</h2>

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

                <FormField id="color" label="Цвет в календаре" hint="Этим цветом будут отмечены занятия инструктора." :error="form.errors.color">
                    <ColorPicker id="color" v-model="form.color" :invalid="Boolean(form.errors.color)" />
                </FormField>

                <div v-if="isEditing">
                    <label class="flex items-center gap-2 text-sm">
                        <input v-model="form.is_active" type="checkbox" class="size-4 rounded border-line accent-sea-600" />
                        Может входить в систему
                    </label>
                    <p v-if="form.errors.is_active" class="mt-1.5 text-sm text-flag">{{ form.errors.is_active }}</p>
                    <p v-else class="mt-1.5 text-sm text-muted">
                        Снимите галочку, чтобы отключить инструктора: он не сможет войти и пропадёт из выбора. Прошлые занятия
                        останутся в истории.
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
                                : 'Сообщите пароль инструктору. Сменить его он сможет в профиле.'
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
                    {{ isEditing ? 'Сохранить изменения' : 'Добавить инструктора' }}
                </PrimaryButton>
                <Link :href="isEditing ? `/instructors/${instructor.id}` : '/instructors'" class="text-sm text-muted hover:text-ink">
                    Отмена
                </Link>
            </div>
        </form>
    </AppLayout>
</template>

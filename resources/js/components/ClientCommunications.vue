<script setup>
import { router, useForm } from '@inertiajs/vue3';
import { nextTick, ref } from 'vue';
import AppIcon from './AppIcon.vue';
import FormField from './FormField.vue';
import PrimaryButton from './PrimaryButton.vue';
import SelectInput from './SelectInput.vue';
import TextArea from './TextArea.vue';
import TextInput from './TextInput.vue';

const props = defineProps({
    clientId: { type: Number, required: true },
    /** Коммуникации клиента: { id, channel, channelLabel, occurredAt, occurredAtLabel, notes, authorName, canManage }. */
    communications: { type: Array, required: true },
    /** Способы связи: { value, label }. */
    channels: { type: Array, required: true },
});

const nowLocal = () => {
    const now = new Date();
    now.setMinutes(now.getMinutes() - now.getTimezoneOffset());
    return now.toISOString().slice(0, 16);
};

/** Идентификатор редактируемой коммуникации, 'new' для новой, null — форма закрыта. */
const editingId = ref(null);
const form = useForm({ channel: props.channels[0].value, occurred_at: '', notes: '' });

const open = async (communication) => {
    form.clearErrors();
    form.channel = communication?.channel ?? props.channels[0].value;
    form.occurred_at = communication?.occurredAt ?? nowLocal();
    form.notes = communication?.notes ?? '';
    editingId.value = communication?.id ?? 'new';
    await nextTick();
    document.getElementById('communication-notes')?.focus();
};

const close = () => {
    editingId.value = null;
    form.clearErrors();
};

const save = () => {
    const options = { preserveScroll: true, onSuccess: close };

    if (editingId.value === 'new') {
        form.post(`/clients/${props.clientId}/communications`, options);
    } else {
        form.patch(`/communications/${editingId.value}`, options);
    }
};

const destroy = (communication) => {
    if (window.confirm('Удалить коммуникацию?')) {
        router.delete(`/communications/${communication.id}`, { preserveScroll: true });
    }
};
</script>

<template>
    <div class="space-y-3">
        <form
            v-if="editingId !== null"
            class="space-y-4 rounded-lg border border-line bg-white p-5"
            novalidate
            @submit.prevent="save"
            @keydown.esc="close"
        >
            <div class="grid gap-4 sm:grid-cols-2">
                <FormField id="communication-channel" label="Способ связи" :error="form.errors.channel">
                    <SelectInput id="communication-channel" v-model="form.channel" :invalid="Boolean(form.errors.channel)">
                        <option v-for="channel in channels" :key="channel.value" :value="channel.value">{{ channel.label }}</option>
                    </SelectInput>
                </FormField>
                <FormField id="communication-occurred-at" label="Дата и время" :error="form.errors.occurred_at">
                    <TextInput
                        id="communication-occurred-at"
                        v-model="form.occurred_at"
                        type="datetime-local"
                        required
                        :invalid="Boolean(form.errors.occurred_at)"
                    />
                </FormField>
            </div>
            <FormField id="communication-notes" label="Содержание" :error="form.errors.notes">
                <TextArea id="communication-notes" v-model="form.notes" required :invalid="Boolean(form.errors.notes)" />
            </FormField>
            <div class="flex items-center gap-3">
                <PrimaryButton :processing="form.processing">Сохранить</PrimaryButton>
                <button type="button" class="px-2 py-2 text-sm text-muted hover:text-ink" @click="close">Отмена</button>
            </div>
        </form>

        <ul v-if="communications.length" class="divide-y divide-line rounded-lg border border-line bg-white" aria-label="Коммуникации клиента">
            <li v-for="communication in communications" :key="communication.id" class="px-5 py-3 text-sm">
                <div class="flex flex-wrap items-start justify-between gap-x-4 gap-y-1">
                    <p class="min-w-0">
                        <span class="font-medium text-ink">{{ communication.channelLabel }}</span>
                        <span class="text-muted"> · {{ communication.occurredAtLabel }}</span>
                        <span v-if="communication.authorName" class="text-muted"> · {{ communication.authorName }}</span>
                    </p>
                    <div v-if="communication.canManage" class="-mr-2 flex shrink-0 gap-1">
                        <button type="button" class="rounded px-2 py-1 text-sm text-sea-700 hover:bg-sea-50" @click="open(communication)">
                            Изменить
                        </button>
                        <button type="button" class="rounded px-2 py-1 text-sm text-flag hover:bg-red-50" @click="destroy(communication)">
                            Удалить
                        </button>
                    </div>
                </div>
                <p class="mt-1 whitespace-pre-line text-ink">{{ communication.notes }}</p>
            </li>
        </ul>

        <div v-else-if="editingId === null" class="rounded-lg border border-dashed border-line bg-white px-6 py-10 text-center">
            <p class="text-base font-medium text-ink">Коммуникаций пока нет</p>
            <p class="mx-auto mt-2 max-w-md text-sm leading-6 text-muted">Записывайте звонки, сообщения и встречи с клиентом, чтобы ничего не потерять.</p>
        </div>

        <button
            v-if="editingId === null"
            type="button"
            class="inline-flex items-center rounded-md border border-line bg-white px-4 py-2 text-sm font-medium text-ink transition-colors hover:bg-surface"
            @click="open(null)"
        >
            <AppIcon name="plus" />
            <span class="ml-1.5">Добавить коммуникацию</span>
        </button>
    </div>
</template>

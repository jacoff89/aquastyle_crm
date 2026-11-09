<script setup>
import { Link, router, useForm, usePoll } from '@inertiajs/vue3';
import { computed, watch } from 'vue';
import PrimaryButton from '../../components/PrimaryButton.vue';
import SelectInput from '../../components/SelectInput.vue';
import AppLayout from '../../layouts/AppLayout.vue';

const props = defineProps({
    /** Telegram пользователя: { isConfigured, isLinked, username, linkUrl }; linkUrl — одноразовая ссылка на бота, пока чат не привязан. */
    telegram: { type: Object, required: true },
    /** Виды уведомлений по разделам: [{ label, types: [{ value, label, personal }] }]. Инструктору — только те, что могут его касаться. */
    groups: { type: Array, required: true },
    /** Доступные охваты: [{ value: 'mine' | 'all', label }]. «Все» есть только у администратора. */
    scopes: { type: Array, required: true },
    /** Что сейчас выбрано: { ClientBooked: 'mine', ... }; не указанные виды не присылаются. */
    choices: { type: Object, required: true },
});

const form = useForm({
    choices: { ...props.choices },
});

/** Администратор для каждого вида выбирает охват, остальным достаточно галочки. */
const choosesScope = computed(() => props.scopes.length > 1);

const scopeOptions = (type) => props.scopes.filter((scope) => type.personal || scope.value !== 'mine');

const isChosen = (type) => Boolean(form.choices[type.value]);

const setChosen = (type, chosen) => {
    if (chosen) {
        form.choices[type.value] = 'mine';
    } else {
        delete form.choices[type.value];
    }
};

const setScope = (type, scope) => {
    if (scope) {
        form.choices[type.value] = scope;
    } else {
        delete form.choices[type.value];
    }
};

const groupState = (group) => {
    const chosen = group.types.filter(isChosen).length;

    return { all: chosen === group.types.length, some: chosen > 0 && chosen < group.types.length };
};

const setGroupChosen = (group, chosen) => {
    group.types.forEach((type) => setChosen(type, chosen));
};

const choicesError = computed(() => Object.entries(form.errors).find(([key]) => key.startsWith('choices'))?.[1] ?? null);

const save = () => {
    form.put('/notifications/settings', { preserveScroll: true });
};

const startLinking = () => {
    router.post('/notifications/telegram', {}, { preserveScroll: true });
};

const unlink = () => {
    if (confirm('Отключить уведомления в Telegram?')) {
        router.delete('/notifications/telegram', { preserveScroll: true });
    }
};

/**
 * Пока пользователь открывает бота по ссылке, страница раз в несколько секунд спрашивает,
 * привязался ли чат, и сама показывает «Подключён».
 */
const { start: startWaiting, stop: stopWaiting } = usePoll(3000, { only: ['telegram'] }, { autoStart: false, keepAlive: true });

const isWaitingForLink = computed(() => Boolean(props.telegram.linkUrl) && !props.telegram.isLinked);

watch(isWaitingForLink, (waiting) => (waiting ? startWaiting() : stopWaiting()), { immediate: true });
</script>

<template>
    <AppLayout title="Настройки уведомлений">
        <template #actions>
            <Link href="/notifications" class="rounded-md border border-line bg-white px-3 py-1.5 text-sm text-ink hover:bg-surface">
                ← К уведомлениям
            </Link>
        </template>

        <div class="max-w-3xl space-y-6">
            <section class="rounded-lg border border-line bg-white p-6" aria-labelledby="telegram-heading">
                <h2 id="telegram-heading" class="text-lg font-semibold">Telegram</h2>

                <p v-if="!telegram.isConfigured" class="mt-2 text-sm text-muted">
                    Отправка в Telegram пока не настроена: администратору нужно указать бота в настройках сервера.
                    Выбрать уведомления можно уже сейчас.
                </p>

                <template v-else-if="telegram.isLinked">
                    <p class="mt-2 text-sm text-ink">
                        <span class="mr-1.5 inline-block size-2 rounded-full bg-sea-600" aria-hidden="true" />
                        Подключён<template v-if="telegram.username"> — @{{ telegram.username }}</template>.
                        Уведомления, выбранные ниже, приходят в чат с ботом.
                    </p>
                    <button
                        type="button"
                        class="mt-4 rounded-md border border-line bg-white px-3 py-1.5 text-sm text-ink hover:bg-surface"
                        @click="unlink"
                    >
                        Отключить
                    </button>
                </template>

                <template v-else-if="telegram.linkUrl">
                    <p class="mt-2 text-sm text-ink">
                        Откройте бота и нажмите «Запустить» (Start). Страница обновится сама, как только чат подключится.
                    </p>
                    <div class="mt-4 flex flex-wrap items-center gap-3">
                        <a
                            :href="telegram.linkUrl"
                            target="_blank"
                            rel="noopener"
                            class="inline-flex items-center justify-center rounded-md bg-sea-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-sea-700"
                        >
                            Открыть бота в Telegram
                        </a>
                        <button type="button" class="text-sm text-sea-700 hover:underline" @click="startLinking">
                            Получить новую ссылку
                        </button>
                    </div>
                    <p class="mt-3 text-xs text-muted">Ссылка одноразовая и действует 30 минут.</p>
                </template>

                <template v-else>
                    <p class="mt-2 text-sm text-muted">
                        Подключите Telegram, чтобы выбранные ниже уведомления приходили в чат с ботом CRM.
                    </p>
                    <button
                        type="button"
                        class="mt-4 inline-flex items-center justify-center rounded-md bg-sea-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-sea-700"
                        @click="startLinking"
                    >
                        Подключить Telegram
                    </button>
                </template>
            </section>

            <section class="rounded-lg border border-line bg-white p-6" aria-labelledby="choices-heading">
                <h2 id="choices-heading" class="text-lg font-semibold">Какие уведомления присылать в Telegram</h2>
                <p class="mt-1 text-sm text-muted">
                    <template v-if="choosesScope">
                        «Касающиеся меня» — о ваших занятиях, снаряжении и учётной записи; «Все» — каждое уведомление этого вида.
                    </template>
                    <template v-else>Приходят только уведомления о ваших занятиях, снаряжении и учётной записи.</template>
                    О своих же изменениях бот не пишет. В CRM уведомления видны все, как и раньше.
                </p>

                <form class="mt-6 space-y-6" novalidate @submit.prevent="save">
                    <fieldset v-for="group in groups" :key="group.label">
                        <legend class="flex w-full items-center gap-2 border-b border-line pb-2 text-sm font-semibold text-ink">
                            <label v-if="!choosesScope" class="flex items-center gap-2">
                                <input
                                    type="checkbox"
                                    class="size-4 rounded border-line accent-sea-600"
                                    :checked="groupState(group).all"
                                    :indeterminate="groupState(group).some"
                                    :aria-label="`Все уведомления раздела «${group.label}»`"
                                    @change="setGroupChosen(group, $event.target.checked)"
                                />
                                {{ group.label }}
                            </label>
                            <template v-else>{{ group.label }}</template>
                        </legend>

                        <ul class="mt-1 divide-y divide-line/60">
                            <li v-for="type in group.types" :key="type.value" class="flex items-center gap-3 py-2">
                                <label v-if="!choosesScope" class="flex flex-1 items-center gap-2 text-sm text-ink">
                                    <input
                                        type="checkbox"
                                        class="size-4 rounded border-line accent-sea-600"
                                        :checked="isChosen(type)"
                                        @change="setChosen(type, $event.target.checked)"
                                    />
                                    {{ type.label }}
                                </label>
                                <template v-else>
                                    <label :for="`scope-${type.value}`" class="flex-1 text-sm text-ink">{{ type.label }}</label>
                                    <div class="w-48 shrink-0">
                                        <SelectInput
                                            :id="`scope-${type.value}`"
                                            :model-value="form.choices[type.value] ?? ''"
                                            @update:model-value="setScope(type, $event)"
                                        >
                                            <option value="">Не присылать</option>
                                            <option v-for="scope in scopeOptions(type)" :key="scope.value" :value="scope.value">
                                                {{ scope.label }}
                                            </option>
                                        </SelectInput>
                                    </div>
                                </template>
                            </li>
                        </ul>
                    </fieldset>

                    <p v-if="choicesError" class="text-sm text-flag">{{ choicesError }}</p>

                    <PrimaryButton :processing="form.processing">Сохранить</PrimaryButton>
                </form>
            </section>
        </div>
    </AppLayout>
</template>

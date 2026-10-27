<script setup>
import { Head, Link, router, usePage } from '@inertiajs/vue3';
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import AppIcon from '../components/AppIcon.vue';
import AppLogo from '../components/AppLogo.vue';
import SidebarLink from '../components/SidebarLink.vue';
import StatusMessage from '../components/StatusMessage.vue';

defineProps({
    title: { type: String, required: true },
});

const page = usePage();
const user = computed(() => page.props.auth.user);
const status = computed(() => page.props.flash.status);
const menuOpen = ref(false);

/**
 * Разделы, которые появятся на следующих этапах, показаны без ссылки,
 * чтобы структура меню была видна сразу. Инструкторов ведёт только администратор.
 */
const sections = computed(() =>
    [
        { label: 'Календарь', href: '/calendar', icon: 'calendar' },
        { label: 'Клиенты', href: '/clients', icon: 'clients' },
        page.props.can.manageInstructors && { label: 'Инструкторы', href: '/instructors', icon: 'instructors' },
    ].filter(Boolean),
);

const settings = computed(() =>
    [
        page.props.can.manageEventTypes && { label: 'Типы занятий', href: '/settings/event-types', icon: 'types' },
        page.props.can.manageUsers && { label: 'Пользователи', href: '/settings/users', icon: 'users' },
    ].filter(Boolean),
);

const isCurrent = (href) => href && (page.url === href || page.url.startsWith(`${href}/`) || page.url.startsWith(`${href}?`));

const closeOnEscape = (event) => {
    if (event.key === 'Escape') {
        menuOpen.value = false;
    }
};

let stopListening = null;

onMounted(() => {
    document.addEventListener('keydown', closeOnEscape);
    stopListening = router.on('navigate', () => {
        menuOpen.value = false;
    });
});

onBeforeUnmount(() => {
    document.removeEventListener('keydown', closeOnEscape);
    stopListening?.();
});
</script>

<template>
    <Head :title="title" />

    <div class="min-h-full lg:flex">
        <!-- Верхняя панель на телефоне -->
        <div class="flex items-center gap-3 bg-depth-900 px-4 py-3 lg:hidden">
            <button
                type="button"
                class="-ml-1 rounded-md p-1.5 text-depth-300 hover:bg-depth-800 hover:text-white"
                aria-label="Открыть меню"
                :aria-expanded="menuOpen"
                @click="menuOpen = true"
            >
                <AppIcon name="menu" />
            </button>
            <AppLogo size="small" />
            <span class="font-semibold text-white">{{ page.props.appName }}</span>
        </div>

        <div
            v-if="menuOpen"
            class="fixed inset-0 z-30 bg-depth-950/50 lg:hidden"
            aria-hidden="true"
            @click="menuOpen = false"
        />

        <aside
            class="fixed inset-y-0 left-0 z-40 flex w-64 flex-col bg-depth-900 text-depth-300 transition-transform duration-200 lg:static lg:min-h-screen lg:translate-x-0 motion-reduce:transition-none"
            :class="menuOpen ? 'translate-x-0' : '-translate-x-full'"
        >
            <div class="flex items-start gap-2 px-4 pt-5 pb-7">
                <Link href="/calendar" class="block flex-1 rounded-xl" :aria-label="`${page.props.appName}: календарь`">
                    <AppLogo />
                </Link>
                <button
                    type="button"
                    class="rounded-md p-1 hover:bg-depth-800 hover:text-white lg:hidden"
                    aria-label="Закрыть меню"
                    @click="menuOpen = false"
                >
                    <AppIcon name="close" />
                </button>
            </div>

            <nav class="flex-1 space-y-8 px-3" aria-label="Основное меню">
                <ul class="space-y-1">
                    <li v-for="item in sections" :key="item.label">
                        <SidebarLink v-if="item.href" :href="item.href" :icon="item.icon" :current="isCurrent(item.href)">
                            {{ item.label }}
                        </SidebarLink>
                        <span v-else class="flex items-center gap-3 px-3 py-2 text-sm text-depth-300/60" aria-disabled="true">
                            <AppIcon :name="item.icon" />
                            {{ item.label }}
                            <span class="ml-auto text-xs">скоро</span>
                        </span>
                    </li>
                </ul>

                <div v-if="settings.length">
                    <p class="px-3 pb-2 text-xs text-depth-300/80">Настройки</p>
                    <ul class="space-y-1">
                        <li v-for="item in settings" :key="item.label">
                            <SidebarLink :href="item.href" :icon="item.icon" :current="isCurrent(item.href)">
                                {{ item.label }}
                            </SidebarLink>
                        </li>
                    </ul>
                </div>
            </nav>

            <div class="border-t border-depth-800 px-3 py-4">
                <div class="px-3 pb-3">
                    <p class="truncate text-sm font-medium text-white">{{ user.name }}</p>
                    <p class="text-xs">{{ user.roleLabel }}</p>
                </div>
                <Link
                    href="/profile"
                    class="flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors"
                    :class="isCurrent('/profile') ? 'bg-depth-700 text-white' : 'hover:bg-depth-800 hover:text-white'"
                >
                    <AppIcon name="profile" />
                    Профиль
                </Link>
                <Link
                    href="/logout"
                    method="post"
                    as="button"
                    class="flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors hover:bg-depth-800 hover:text-white"
                >
                    <AppIcon name="logout" />
                    Выйти
                </Link>
            </div>
        </aside>

        <main class="min-w-0 flex-1 px-4 py-6 sm:px-8 lg:py-10">
            <div class="mx-auto max-w-6xl">
                <div class="flex flex-wrap items-center justify-between gap-4">
                    <h1 class="text-2xl font-semibold tracking-tight text-ink">{{ title }}</h1>
                    <slot name="actions" />
                </div>
                <StatusMessage :message="status" class="mt-4 max-w-xl" />
                <div class="mt-6">
                    <slot />
                </div>
            </div>
        </main>
    </div>
</template>

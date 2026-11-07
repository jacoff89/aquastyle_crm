<script setup>
import { Link } from '@inertiajs/vue3';
import AppIcon from './AppIcon.vue';

defineProps({
    href: { type: String, required: true },
    icon: { type: String, required: true },
    current: { type: Boolean, default: false },
    /** Счётчик справа от пункта, например непрочитанные уведомления; не показывается, когда пуст. */
    badge: { type: String, default: null },
    /** Подпись счётчика для экранных дикторов. */
    badgeLabel: { type: String, default: null },
});
</script>

<template>
    <Link
        :href="href"
        class="flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors"
        :class="current ? 'bg-depth-700 text-white' : 'hover:bg-depth-800 hover:text-white'"
        :aria-current="current ? 'page' : undefined"
    >
        <AppIcon :name="icon" />
        <slot />
        <span
            v-if="badge"
            class="ml-auto min-w-5 rounded-full bg-flag px-1.5 py-0.5 text-center text-xs leading-none font-semibold text-white"
            :aria-label="badgeLabel ?? undefined"
        >
            {{ badge }}
        </span>
    </Link>
</template>

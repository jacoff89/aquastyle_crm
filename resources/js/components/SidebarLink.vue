<script setup>
import { Link } from '@inertiajs/vue3';
import AppIcon from './AppIcon.vue';

defineProps({
    href: { type: String, required: true },
    icon: { type: String, required: true },
    current: { type: Boolean, default: false },
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
    </Link>
</template>

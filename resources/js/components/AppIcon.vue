<script setup>
// Небольшой набор контурных иконок 24×24 для меню и кнопок.
defineProps({
    name: { type: String, required: true },
});
</script>

<template>
    <svg
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="1.6"
        stroke-linecap="round"
        stroke-linejoin="round"
        class="size-5 shrink-0"
        aria-hidden="true"
    >
        <template v-if="name === 'calendar'">
            <rect x="3.5" y="5" width="17" height="15" rx="2" />
            <path d="M3.5 10h17M8 3v4M16 3v4" />
        </template>
        <template v-else-if="name === 'clients'">
            <circle cx="9" cy="8.5" r="3.5" />
            <path d="M2.5 19.5c.8-3.3 3.4-5 6.5-5s5.7 1.7 6.5 5" />
            <path d="M15.5 5.3a3.5 3.5 0 0 1 0 6.4M17.5 14.8c2 .6 3.4 2.2 4 4.7" />
        </template>
        <template v-else-if="name === 'instructors'">
            <circle cx="12" cy="7.5" r="3.5" />
            <path d="M5 20c.9-3.6 3.6-5.5 7-5.5s6.1 1.9 7 5.5" />
            <path d="m12 14.5 1.4 2.5L12 20l-1.4-3Z" />
        </template>
        <template v-else-if="name === 'types'">
            <path d="M4 6h16M4 12h16M4 18h10" />
        </template>
        <template v-else-if="name === 'users'">
            <circle cx="12" cy="9" r="3.5" />
            <path d="M5.5 19.5c1-3 3.6-4.5 6.5-4.5s5.5 1.5 6.5 4.5" />
            <rect x="2.5" y="2.5" width="19" height="19" rx="4" />
        </template>
        <template v-else-if="name === 'profile'">
            <circle cx="12" cy="12" r="9" />
            <circle cx="12" cy="10" r="3" />
            <path d="M6.5 18.5c1.2-2.2 3.2-3.3 5.5-3.3s4.3 1.1 5.5 3.3" />
        </template>
        <template v-else-if="name === 'logout'">
            <path d="M14 4h4a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-4" />
            <path d="M10 8 6 12l4 4M6 12h9" />
        </template>
        <template v-else-if="name === 'menu'">
            <path d="M4 7h16M4 12h16M4 17h16" />
        </template>
        <template v-else-if="name === 'close'">
            <path d="m6 6 12 12M18 6 6 18" />
        </template>
        <template v-else-if="name === 'up'">
            <path d="m6 14 6-6 6 6" />
        </template>
        <template v-else-if="name === 'down'">
            <path d="m6 10 6 6 6-6" />
        </template>
        <template v-else-if="name === 'plus'">
            <path d="M12 5v14M5 12h14" />
        </template>
    </svg>
</template>

<script setup>
defineProps({
    invalid: { type: Boolean, default: false },
});

const model = defineModel({ type: [String, Number, null], default: '' });
</script>

<template>
    <select
        v-model="model"
        class="block w-full rounded-md border bg-white px-3 py-2 text-base text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-sea-600/30 sm:text-sm"
        :class="invalid ? 'border-flag' : 'border-line focus-visible:border-sea-600'"
        :aria-invalid="invalid"
    >
        <slot />
    </select>
</template>

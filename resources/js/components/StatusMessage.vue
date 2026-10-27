<script setup>
defineProps({
    message: { type: String, default: '' },
});
</script>

<template>
    <p
        v-if="message"
        role="status"
        class="rounded-md border border-sea-100 bg-sea-50 px-3 py-2 text-sm text-sea-700"
    >
        {{ message }}
    </p>
</template>

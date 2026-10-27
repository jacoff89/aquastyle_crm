<script setup>
// Знак бренда: флаг «ныряльщик под водой» — красное полотнище с белой диагональю.
defineProps({
    size: { type: Number, default: 32 },
});
</script>

<template>
    <svg :width="size" :height="size" viewBox="0 0 32 32" aria-hidden="true">
        <defs>
            <clipPath id="dive-flag-shape">
                <rect width="32" height="32" rx="6" />
            </clipPath>
        </defs>
        <g clip-path="url(#dive-flag-shape)">
            <rect width="32" height="32" fill="var(--color-flag)" />
            <path d="M0 0h6l26 26v6h-6L0 6Z" fill="#fff" />
        </g>
    </svg>
</template>

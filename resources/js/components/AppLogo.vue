<script setup>
import logoUrl from '../../images/logo-aquastyle.webp';

// Логотип дайвинг-центра на красной плашке.
// small — маленький знак в мобильной шапке, large — во всю ширину родителя.
defineProps({
    size: { type: String, default: 'large', validator: (value) => ['small', 'large'].includes(value) },
});
</script>

<template>
    <span
        class="flex items-center justify-center bg-flag"
        :class="size === 'small' ? 'h-10 w-13 rounded-md p-1' : 'w-full rounded-xl p-3'"
    >
        <img
            :src="logoUrl"
            alt="Дайвинг-центр «Аквастиль»"
            width="640"
            height="496"
            class="h-auto max-h-full w-auto max-w-full"
        />
    </span>
</template>

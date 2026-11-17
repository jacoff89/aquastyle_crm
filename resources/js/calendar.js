import { http } from '@inertiajs/vue3';

/**
 * Общее для страниц с календарём vue-cal: календаря занятий и календаря коммуникаций.
 * Их внешний вид — в resources/css/calendar.css.
 */

const pad = (number) => String(number).padStart(2, '0');

/** Дата в виде YYYY-MM-DD по местным часам браузера: vue-cal работает с ними же. */
export const formatDate = (date) => `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;

/** Дата и время в виде «YYYY-MM-DD HH:MM», как их отдаёт и принимает сервер. */
export const formatDateTime = (date) => `${formatDate(date)} ${pad(date.getHours())}:${pad(date.getMinutes())}`;

/**
 * Запрос к серверу. Ответы 4xx приходят как исключение с полем response,
 * поэтому здесь они превращаются в обычный результат { status, data }.
 */
export const request = async (method, url, data = null) => {
    try {
        const response = await http.getClient().request({
            method,
            url,
            data,
            headers: { Accept: 'application/json' },
        });

        return { status: response.status, data: response.data ? JSON.parse(response.data) : null };
    } catch (error) {
        if (error?.response) {
            return { status: error.response.status, data: error.response.data ? JSON.parse(error.response.data) : null };
        }

        return { status: 0, data: null };
    }
};

/** Белый или тёмный текст — что лучше читается на цвете пользователя (инструктора, создателя коммуникации). */
export const textColorFor = (hex) => {
    const match = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex ?? '');

    if (!match) {
        return '#ffffff';
    }

    const [red, green, blue] = match.slice(1).map((part) => parseInt(part, 16) / 255);
    const luminance = 0.2126 * red + 0.7152 * green + 0.0722 * blue;

    return luminance > 0.6 ? '#12262e' : '#ffffff';
};

const shortWeekdays = {
    понедельник: 'пн',
    вторник: 'вт',
    среда: 'ср',
    четверг: 'чт',
    пятница: 'пт',
    суббота: 'сб',
    воскресенье: 'вс',
};

/** Короткое название дня недели для заголовка колонки на телефоне. */
export const shortWeekday = (heading) => shortWeekdays[heading.label.toLowerCase()] ?? heading.label.slice(0, 2).toLowerCase();

/**
 * Запоминает в адресе вид, дату и фильтры календаря, чтобы после обновления страницы
 * он открылся там же, где был, а ссылкой можно было поделиться. Пустой фильтр убирается из адреса.
 */
export const rememberInAddress = (view, date, filters) => {
    const url = new URL(window.location.href);
    url.searchParams.set('view', view);
    url.searchParams.set('date', formatDate(date));

    for (const [name, value] of Object.entries(filters)) {
        if (value === '' || value === null) {
            url.searchParams.delete(name);
        } else {
            url.searchParams.set(name, value);
        }
    }

    window.history.replaceState(window.history.state, '', url);
};

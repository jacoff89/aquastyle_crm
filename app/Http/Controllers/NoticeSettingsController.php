<?php

namespace App\Http\Controllers;

use App\Enums\NoticeType;
use App\Enums\TelegramNoticeScope;
use App\Notifications\Telegram\TelegramBot;
use App\Notifications\Telegram\TelegramLinkTokens;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use Inertia\Inertia;
use Inertia\Response;

/**
 * The notification settings of the signed-in user: the linked Telegram chat and which notices go there.
 * An instructor chooses among the notices that can concern them; an administrator among all of them,
 * and for each type whether they want only the notices that concern them or every one.
 *
 * It is a preference of the user, not a change of the account, so no domain event announces it.
 */
class NoticeSettingsController extends Controller
{
    public function edit(Request $request, TelegramBot $bot, TelegramLinkTokens $tokens): Response
    {
        $user = $request->user();

        return Inertia::render('notifications/Settings', [
            'telegram' => function () use ($user, $bot, $tokens): array {
                $pendingToken = $user->hasTelegram() ? null : $tokens->pendingFor($user);

                return [
                    'isConfigured' => $bot->isConfigured(),
                    'isLinked' => $user->hasTelegram(),
                    'username' => $user->telegram_username,
                    'linkUrl' => $pendingToken === null ? null : $bot->startLink($pendingToken),
                ];
            },
            'groups' => NoticeType::groupedFor($user),
            'scopes' => TelegramNoticeScope::optionsFor($user),
            'choices' => (object) $user->telegramNoticeChoices(),
        ]);
    }

    public function update(Request $request): RedirectResponse
    {
        $user = $request->user();
        $types = array_map(fn (NoticeType $type): string => $type->value, NoticeType::availableTo($user));

        $validated = $request->validate([
            'choices' => ['present', 'array:'.implode(',', $types)],
            'choices.*' => ['required', Rule::enum(TelegramNoticeScope::class)->only(TelegramNoticeScope::availableTo($user))],
        ]);

        $user->telegram_notices = $validated['choices'];
        $user->save();

        return back()->with('status', 'Настройки уведомлений сохранены.');
    }
}

<?php

namespace App\Http\Controllers;

use App\Notifications\Telegram\TelegramBot;
use App\Notifications\Telegram\TelegramException;
use App\Notifications\Telegram\TelegramLinkTokens;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

/**
 * Linking the signed-in user's Telegram chat. Linking gives a one-time link to the bot,
 * shown on the settings page; the chat is linked when the user presses "Start" there
 * (see HandleTelegramUpdate).
 */
class TelegramLinkController extends Controller
{
    public function store(Request $request, TelegramBot $bot, TelegramLinkTokens $tokens): RedirectResponse
    {
        abort_unless($bot->isConfigured(), 404);

        $tokens->issueFor($request->user());

        return back();
    }

    public function destroy(Request $request, TelegramBot $bot, TelegramLinkTokens $tokens): RedirectResponse
    {
        $user = $request->user();
        $chatId = $user->telegram_chat_id;

        $tokens->forgetFor($user);
        $user->unlinkTelegram();

        if ($chatId !== null && $bot->isConfigured()) {
            try {
                $bot->sendMessage($chatId, 'Уведомления CRM в этот чат отключены.');
            } catch (TelegramException $exception) {
                report($exception);
            }
        }

        return back()->with('status', 'Telegram отключён.');
    }
}

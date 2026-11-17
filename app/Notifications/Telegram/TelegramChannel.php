<?php

namespace App\Notifications\Telegram;

use App\Models\User;
use Illuminate\Notifications\Notification;
use Illuminate\Support\Facades\Log;

/**
 * The "telegram" notification channel: sends what the notification's toTelegram() returns
 * to the chat the notifiable routes to.
 *
 * When the chat is gone for good (the user blocked the bot), the chat is unlinked instead of
 * retrying, so that the user stops getting attempts until they link Telegram again.
 * Outside production (`services.telegram.deliver` is off) nothing is sent: the message is written to the log.
 * Any other failure is thrown, and the queue retries the notification.
 */
class TelegramChannel
{
    public function __construct(private TelegramBot $bot) {}

    /**
     * @throws TelegramException
     */
    public function send(object $notifiable, Notification $notification): void
    {
        $chatId = $notifiable->routeNotificationFor('telegram', $notification);

        if ($chatId === null || ! $this->bot->isConfigured()) {
            return;
        }

        $message = $notification->toTelegram($notifiable);

        if (! config('services.telegram.deliver')) {
            Log::info('Telegram (не production, не отправлено)', ['chat_id' => $chatId, 'text' => $message]);

            return;
        }

        try {
            $this->bot->sendMessage((int) $chatId, $message);
        } catch (TelegramException $exception) {
            if (! $exception->isChatUnavailable() || ! $notifiable instanceof User) {
                throw $exception;
            }

            $notifiable->unlinkTelegram();
        }
    }
}

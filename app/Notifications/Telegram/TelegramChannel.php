<?php

namespace App\Notifications\Telegram;

use App\Models\User;
use Illuminate\Notifications\Notification;

/**
 * The "telegram" notification channel: sends what the notification's toTelegram() returns
 * to the chat the notifiable routes to.
 *
 * When the chat is gone for good (the user blocked the bot), the chat is unlinked instead of
 * retrying, so that the user stops getting attempts until they link Telegram again.
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

        try {
            $this->bot->sendMessage((int) $chatId, $notification->toTelegram($notifiable));
        } catch (TelegramException $exception) {
            if (! $exception->isChatUnavailable() || ! $notifiable instanceof User) {
                throw $exception;
            }

            $notifiable->unlinkTelegram();
        }
    }
}

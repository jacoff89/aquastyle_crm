<?php

namespace App\Console\Commands;

use App\Actions\HandleTelegramUpdate;
use App\Notifications\Telegram\TelegramBot;
use App\Notifications\Telegram\TelegramException;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;

/**
 * Points the bot's webhook at this installation, so that "/start" from the link on the settings page
 * reaches the CRM. Run it once after deploying with the bot configured, or after changing APP_URL.
 * Telegram only posts to a public HTTPS address; locally use telegram:poll instead.
 */
#[Signature('telegram:webhook
    {--delete : Отключить webhook, например чтобы получать обновления через telegram:poll}')]
#[Description('Подключить webhook Telegram-бота к этому сайту')]
class TelegramWebhook extends Command
{
    public function handle(TelegramBot $bot): int
    {
        if (! $bot->isConfigured()) {
            $this->error('Бот не настроен: задайте TELEGRAM_BOT_TOKEN и TELEGRAM_BOT_USERNAME в .env.');

            return self::FAILURE;
        }

        try {
            if ($this->option('delete')) {
                $bot->deleteWebhook();
                $this->info('Webhook отключён.');

                return self::SUCCESS;
            }

            $url = route('telegram.webhook');
            $bot->setWebhook($url, HandleTelegramUpdate::ALLOWED_UPDATES);
            $this->info("Webhook подключён: {$url}");
        } catch (TelegramException $exception) {
            $this->error("Telegram ответил ошибкой: {$exception->getMessage()}");

            return self::FAILURE;
        }

        return self::SUCCESS;
    }
}

<?php

namespace Tests\Feature\Events;

use App\Enums\NoticeType;
use App\Events\DomainEvent;
use ReflectionClass;
use Tests\TestCase;

/**
 * Every domain event is a kind of notice people can choose in the settings, so a new event
 * cannot silently stay out of Telegram.
 */
class NoticeTypeTest extends TestCase
{
    public function test_every_domain_event_has_a_notice_type_and_every_type_an_event(): void
    {
        $events = collect(glob(app_path('Events/*/*.php')))
            ->map(fn (string $path): string => 'App\\Events\\'.basename(dirname($path)).'\\'.basename($path, '.php'))
            ->filter(fn (string $class): bool => is_subclass_of($class, DomainEvent::class) && ! (new ReflectionClass($class))->isAbstract())
            ->map(fn (string $class): string => class_basename($class))
            ->sort()
            ->values()
            ->all();

        $types = collect(NoticeType::cases())->map(fn (NoticeType $type): string => $type->value)->sort()->values()->all();

        $this->assertSame($events, $types);
    }
}

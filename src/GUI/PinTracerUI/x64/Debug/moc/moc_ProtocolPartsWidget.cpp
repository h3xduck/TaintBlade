/****************************************************************************
** Meta object code from reading C++ file 'ProtocolPartsWidget.h'
**
** Created by: The Qt Meta Object Compiler version 68 (Qt 6.5.1)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../include/widgets/protocol/ProtocolPartsWidget.h"
#include <QtCore/qmetatype.h>

#if __has_include(<QtCore/qtmochelpers.h>)
#include <QtCore/qtmochelpers.h>
#else
QT_BEGIN_MOC_NAMESPACE
#endif


#include <memory>

#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'ProtocolPartsWidget.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 68
#error "This file was generated using the moc from 6.5.1. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

#ifndef Q_CONSTINIT
#define Q_CONSTINIT
#endif

QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
QT_WARNING_DISABLE_GCC("-Wuseless-cast")
namespace {

#ifdef QT_MOC_HAS_STRINGDATA
struct qt_meta_stringdata_CLASSProtocolPartsWidgetENDCLASS_t {};
static constexpr auto qt_meta_stringdata_CLASSProtocolPartsWidgetENDCLASS = QtMocHelpers::stringData(
    "ProtocolPartsWidget",
    "onSelectedProtocolBuffer",
    "",
    "bufferIndex",
    "onSelectedBufferWord",
    "wordIndex",
    "onSelectedBufferPointer",
    "pointerIndex",
    "onTopListItemClicked",
    "QListWidgetItem*",
    "onMidListItemClicked",
    "onBotListItemClicked"
);
#else  // !QT_MOC_HAS_STRING_DATA
struct qt_meta_stringdata_CLASSProtocolPartsWidgetENDCLASS_t {
    uint offsetsAndSizes[24];
    char stringdata0[20];
    char stringdata1[25];
    char stringdata2[1];
    char stringdata3[12];
    char stringdata4[21];
    char stringdata5[10];
    char stringdata6[24];
    char stringdata7[13];
    char stringdata8[21];
    char stringdata9[17];
    char stringdata10[21];
    char stringdata11[21];
};
#define QT_MOC_LITERAL(ofs, len) \
    uint(sizeof(qt_meta_stringdata_CLASSProtocolPartsWidgetENDCLASS_t::offsetsAndSizes) + ofs), len 
Q_CONSTINIT static const qt_meta_stringdata_CLASSProtocolPartsWidgetENDCLASS_t qt_meta_stringdata_CLASSProtocolPartsWidgetENDCLASS = {
    {
        QT_MOC_LITERAL(0, 19),  // "ProtocolPartsWidget"
        QT_MOC_LITERAL(20, 24),  // "onSelectedProtocolBuffer"
        QT_MOC_LITERAL(45, 0),  // ""
        QT_MOC_LITERAL(46, 11),  // "bufferIndex"
        QT_MOC_LITERAL(58, 20),  // "onSelectedBufferWord"
        QT_MOC_LITERAL(79, 9),  // "wordIndex"
        QT_MOC_LITERAL(89, 23),  // "onSelectedBufferPointer"
        QT_MOC_LITERAL(113, 12),  // "pointerIndex"
        QT_MOC_LITERAL(126, 20),  // "onTopListItemClicked"
        QT_MOC_LITERAL(147, 16),  // "QListWidgetItem*"
        QT_MOC_LITERAL(164, 20),  // "onMidListItemClicked"
        QT_MOC_LITERAL(185, 20)   // "onBotListItemClicked"
    },
    "ProtocolPartsWidget",
    "onSelectedProtocolBuffer",
    "",
    "bufferIndex",
    "onSelectedBufferWord",
    "wordIndex",
    "onSelectedBufferPointer",
    "pointerIndex",
    "onTopListItemClicked",
    "QListWidgetItem*",
    "onMidListItemClicked",
    "onBotListItemClicked"
};
#undef QT_MOC_LITERAL
#endif // !QT_MOC_HAS_STRING_DATA
} // unnamed namespace

Q_CONSTINIT static const uint qt_meta_data_CLASSProtocolPartsWidgetENDCLASS[] = {

 // content:
      11,       // revision
       0,       // classname
       0,    0, // classinfo
       6,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       3,       // signalCount

 // signals: name, argc, parameters, tag, flags, initial metatype offsets
       1,    1,   50,    2, 0x06,    1 /* Public */,
       4,    1,   53,    2, 0x06,    3 /* Public */,
       6,    1,   56,    2, 0x06,    5 /* Public */,

 // slots: name, argc, parameters, tag, flags, initial metatype offsets
       8,    1,   59,    2, 0x0a,    7 /* Public */,
      10,    1,   62,    2, 0x0a,    9 /* Public */,
      11,    1,   65,    2, 0x0a,   11 /* Public */,

 // signals: parameters
    QMetaType::Void, QMetaType::Int,    3,
    QMetaType::Void, QMetaType::Int,    5,
    QMetaType::Void, QMetaType::Int,    7,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 9,    2,
    QMetaType::Void, 0x80000000 | 9,    2,
    QMetaType::Void, 0x80000000 | 9,    2,

       0        // eod
};

Q_CONSTINIT const QMetaObject ProtocolPartsWidget::staticMetaObject = { {
    QMetaObject::SuperData::link<QWidget::staticMetaObject>(),
    qt_meta_stringdata_CLASSProtocolPartsWidgetENDCLASS.offsetsAndSizes,
    qt_meta_data_CLASSProtocolPartsWidgetENDCLASS,
    qt_static_metacall,
    nullptr,
    qt_incomplete_metaTypeArray<qt_meta_stringdata_CLASSProtocolPartsWidgetENDCLASS_t,
        // Q_OBJECT / Q_GADGET
        QtPrivate::TypeAndForceComplete<ProtocolPartsWidget, std::true_type>,
        // method 'onSelectedProtocolBuffer'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<int, std::false_type>,
        // method 'onSelectedBufferWord'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<int, std::false_type>,
        // method 'onSelectedBufferPointer'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<int, std::false_type>,
        // method 'onTopListItemClicked'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<QListWidgetItem *, std::false_type>,
        // method 'onMidListItemClicked'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<QListWidgetItem *, std::false_type>,
        // method 'onBotListItemClicked'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<QListWidgetItem *, std::false_type>
    >,
    nullptr
} };

void ProtocolPartsWidget::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<ProtocolPartsWidget *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->onSelectedProtocolBuffer((*reinterpret_cast< std::add_pointer_t<int>>(_a[1]))); break;
        case 1: _t->onSelectedBufferWord((*reinterpret_cast< std::add_pointer_t<int>>(_a[1]))); break;
        case 2: _t->onSelectedBufferPointer((*reinterpret_cast< std::add_pointer_t<int>>(_a[1]))); break;
        case 3: _t->onTopListItemClicked((*reinterpret_cast< std::add_pointer_t<QListWidgetItem*>>(_a[1]))); break;
        case 4: _t->onMidListItemClicked((*reinterpret_cast< std::add_pointer_t<QListWidgetItem*>>(_a[1]))); break;
        case 5: _t->onBotListItemClicked((*reinterpret_cast< std::add_pointer_t<QListWidgetItem*>>(_a[1]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (ProtocolPartsWidget::*)(int );
            if (_t _q_method = &ProtocolPartsWidget::onSelectedProtocolBuffer; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (ProtocolPartsWidget::*)(int );
            if (_t _q_method = &ProtocolPartsWidget::onSelectedBufferWord; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (ProtocolPartsWidget::*)(int );
            if (_t _q_method = &ProtocolPartsWidget::onSelectedBufferPointer; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 2;
                return;
            }
        }
    }
}

const QMetaObject *ProtocolPartsWidget::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *ProtocolPartsWidget::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_CLASSProtocolPartsWidgetENDCLASS.stringdata0))
        return static_cast<void*>(this);
    return QWidget::qt_metacast(_clname);
}

int ProtocolPartsWidget::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QWidget::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 6)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 6;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 6)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 6;
    }
    return _id;
}

// SIGNAL 0
void ProtocolPartsWidget::onSelectedProtocolBuffer(int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void ProtocolPartsWidget::onSelectedBufferWord(int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}

// SIGNAL 2
void ProtocolPartsWidget::onSelectedBufferPointer(int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 2, _a);
}
QT_WARNING_POP
